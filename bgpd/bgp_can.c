/*********************************************
 * @File name: bgp_can.c
 * @Author: zyh, cz
 * @Version: 1.0
 * @Date: 2021-9-29
 * @Description: CAN related functions' implementation
 * @Copyright: © 2023 BUPT. All rights reserved.
 **********************************************/

#include <arpa/inet.h>
#include <mysql/mysql.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <float.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_can.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_packet.h"

#define is_error(ptr) ((unsigned long)ptr > (unsigned long)-4000L)

static struct timeval last_netstate_update, last_comstate_update;
const char *ns_log = "/var/tmp/can.netstate.log";
const char *cs_rcv_log = "/var/tmp/can.comstate.receive.log";
const char *cs_snd_log = "var/tmp/can.comstate.send.log";
const char *cs_upd_log = "/var/tmp/can.comstate.update.log";
const char *debug_http_log = "/var/tmp/can.debug.http.log";
const char *debug_adver_log = "/var/tmp/can.debug.adver.log";
const char *debug_mtx_log = "/var/tmp/can.debug.mtx.log";
static int ns_log_cnt = 0, cs_rcv_log_cnt = 0, cs_snd_log_cnt = 0, cs_upd_log_cnt = 0,
    debug_http_log_cnt = 0, debug_adver_log_cnt = 0, debug_mtx_log_cnt = 0;
int ns_skt = 0, cs_skt = 0;

static pthread_mutex_t *com_list_mtx;
static struct com_list *com_list;
static int com_list_size;

int socket_open_http(struct bgp *bgp);

static struct com_node *com_node_new(struct com_node *pre,
				     struct com_node *next,
				     struct comstate *entry)
{
	struct com_node *com_node = XMALLOC(MTYPE_TMP, sizeof(struct com_node));
	com_node->pre = pre;
	com_node->next = next;
	com_node->entry = entry;
	return com_node;
}

static struct com_list *com_list_new()
{
	struct com_list *com_list = XMALLOC(MTYPE_TMP, sizeof(struct com_list));
	com_list->head = com_node_new(NULL, NULL, NULL);
	com_list->tail = com_node_new(NULL, NULL, NULL);
	com_list->head->next = com_list->tail;
	com_list->tail->pre = com_list->head;
	return com_list;
}

static void com_list_insert_tail(struct com_list *com_list,
				 struct comstate *entry)
{
	frr_with_mutex (com_list_mtx) {
		struct comstate *com =
			XMALLOC(MTYPE_TMP, sizeof(struct comstate));
		com->sid_addr = entry->sid_addr;
		com->egress_addr = entry->egress_addr;
		com->com_usage = entry->com_usage;
		com->mem_usage = entry->mem_usage;
		com->pref = entry->pref;
		struct com_node *new_node =
			com_node_new(com_list->tail->pre, com_list->tail, com);
		new_node->pre->next = new_node;
		new_node->next->pre = new_node;
		com_list_size++;
	}
}

static void com_list_remove_head(struct com_list *com_list)
{
	if (!com_list_size)
		return;
	frr_with_mutex (com_list_mtx) {
		struct com_node *target = com_list->head->next;
		target->pre->next = target->next;
		target->next->pre = target->pre;
		XFREE(MTYPE_TMP, target->entry);
		XFREE(MTYPE_TMP, target);
		com_list_size--;
	}
}

static struct peer_can *peer_can_new(struct peer *peer)
{
	struct peer_can *peer_can = XMALLOC(MTYPE_TMP, sizeof(struct peer_can));
	peer_can->peer = peer;
	return peer_can;
}

static void peer_can_del(void *peer_can)
{
	XFREE(MTYPE_TMP, peer_can);
}

/* List of peers we are sending advertisement for, and associated mutex. */
static pthread_mutex_t *peerhash_can_mtx;
static pthread_cond_t *peerhash_can_cond;
static struct hash *peerhash_can;

static bool peer_hash_can_cmp(const void *f, const void *s)
{
	const struct peer_can *p1 = f;
	const struct peer_can *p2 = s;

	return p1->peer == p2->peer;
}

static unsigned int peer_hash_can_key(const void *arg)
{
	const struct peer_can *peer_can = arg;
	return (uintptr_t)peer_can->peer;
}

/***************************************************
 * Function name: retrieve_netstate
 * Description: search for target eip's netstate in local netstate table
 * Parameters:
 * 		@eip		Target Egress IP
 * 		@bgp		Default BGP instance
 * Return: target eip's netstate, or NULL if search failed
 *
 ****************************************************/
static struct netstate *retrieve_netstate(struct in6_addr *eip, struct bgp *bgp)
{
	int s = bgp->net_table_size;
	if (!s)
		return NULL;
	int i = 0;
	for (i = 0; i < s; i++) {
		if (!memcmp(&bgp->net_table_entry[i]->dest_addr, eip,
			    sizeof(struct in6_addr)))
			return bgp->net_table_entry[i];
	}
	return NULL;
}

/***************************************************
 * Function name: update_can_rib
 * Description: update CAN RIB
 * Parameters:
 * 		@sid		Service ID
 * 		@eip		Target Egress IP
 * 		@bgp 		Default BGP instance
 * Return: NULL
 *
 ****************************************************/
static void update_can_rib(struct in6_addr *sid, struct in6_addr *eip,
			   struct bgp *bgp)
{
	int s = bgp->can_rib_size;
	int i = 0;
	for (i = 0; i < s; i++)
		if (!memcmp(sid, &bgp->can_rib_entry[i]->sid, sizeof(struct in6_addr))) {
			memcpy(&bgp->can_rib_entry[i]->eip, eip, sizeof(struct in6_addr));
			return;
		}
	bgp->can_rib_entry[s] = XMALLOC(MTYPE_TMP, sizeof(struct can_rib));
	memcpy(&bgp->can_rib_entry[s]->sid, sid, sizeof(struct in6_addr));
	memcpy(&bgp->can_rib_entry[s]->eip, eip, sizeof(struct in6_addr));
	bgp->can_rib_size++;
	return;
}

/***************************************************
 * Function name: write_log
 * Description: write log into a file
 * Parameters:
 * 		@file		Log file name
 * 		@text		Log content
 * 		@row_cnt	Log file row count
 * Return: NULL
 *
 ****************************************************/
void write_log(const char *file, char *text, int *row_cnt)
{
	if (*row_cnt >= LOG_MAX_ROW) {
		FILE *fp = fopen(file, "w+");
		if (!fp)
			return;
		fclose(fp);
		*row_cnt = 0;
	}
	FILE *fp = fopen(file, "a+");
	if (!fp)
		return;
	fputs(text, fp);
	(*row_cnt)++;
	fclose(fp);
}

/***************************************************
 * Function name: get_local_time
 * Description: get local time
 * Parameters: NULL
 * Return: Current formated time
 *
 ****************************************************/
static char *get_local_time(void)
{
	char *time_buffer = XMALLOC(MTYPE_TMP, 100 * sizeof(char));
	time_t rawtime;
	struct tm *timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	memset(time_buffer, 0, 100);
	sprintf(time_buffer, "%04d-%02d-%02d %02d:%02d:%02d",
		(timeinfo->tm_year + 1900), (1 + timeinfo->tm_mon),
		timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min,
		timeinfo->tm_sec);
	return time_buffer;
}

/***************************************************
 * Function name: write_rib
 * Description: write rib into the rib file
 * Parameters:
 * 		@bgp		Default bgp instance
 * Return: NULL
 *
 ****************************************************/
static void write_rib(struct bgp *bgp)
{
	FILE *fp = NULL;
	const char *filename = "/var/tmp/can.rib";
	fp = fopen(filename, "w+");
	int i = 0, crs = bgp->can_rib_size;
	fputs("SID\t\tEIP\n", fp);
	char sid_str[INET6_ADDRSTRLEN];
	char eip_str[INET6_ADDRSTRLEN];
	for (i = 0; i < crs; i++) {
		inet_ntop(AF_INET6, &bgp->can_rib_entry[i]->sid, sid_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &bgp->can_rib_entry[i]->eip, eip_str, INET6_ADDRSTRLEN);
		fprintf(fp, "%s\t%s\n", sid_str, eip_str);
	}
	fclose(fp);
	return;
}

/***************************************************
 * Function name: path_calculation
 * Description: calculate rib by comstate and netstate information
 * Parameters:
 * 		@bgp		Default bgp instance
 * Return: Calulation results count, or 0 if error
 *
 ****************************************************/
static int path_calculation(struct bgp *bgp)
{
	int cts = bgp->com_table_size;
	int nts = bgp->net_table_size;
	int sls = bgp->sid_list_size;
	int i = 0, j = 0, cnt = 0;
	struct netstate *ns;
	struct comstate *cs;
	struct in6_addr eip;
	float cu_min = 100.0, mu_min = 100.0;
	float l_min = 100.0, d_min = FLT_MAX, j_min = FLT_MAX;
	int flag = 0;
	if (!sls || !nts || !cts)
		return 0;
	for (i = 0; i < sls; i++) {
		cu_min = 100.0, mu_min = 100.0;
		l_min = 100.0, d_min = FLT_MAX, j_min = FLT_MAX;
		flag = 0;
		memset(&eip, 0, sizeof(struct in6_addr));
		for (j = 0; j < cts; j++) {
			cs = bgp->com_table_entry[j];
			if (!memcmp(&bgp->sid_list[i], cs,
				    sizeof(struct in6_addr))) {
				if (cs->com_usage < cu_min) {
					ns = retrieve_netstate(&cs->egress_addr,
							       bgp);
					if (!ns) break;
					memcpy(&eip, &cs->egress_addr,
					       sizeof(struct in6_addr));
					cu_min = cs->com_usage;
					mu_min = cs->mem_usage;
					l_min = ns->loss;
					d_min = ns->delay;
					j_min = ns->jitter;
					flag = 1;
				} else if (cs->com_usage == cu_min) {
					ns = retrieve_netstate(&cs->egress_addr,
							       bgp);
					if (!ns) break;
					if (ns->loss < l_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else if (ns->loss > l_min)
						continue;
					else if (ns->delay < d_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else if (ns->delay > d_min)
						continue;
					else if (ns->jitter < j_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else
						continue;
				} else if (cs->com_usage > cu_min)
					continue;
				else if (cs->mem_usage < mu_min) {
					cu_min = cs->com_usage;
					mu_min = cs->mem_usage;
					memcpy(&eip, &cs->egress_addr,
					       sizeof(struct in6_addr));
					flag = 1;
				} else if (cs->mem_usage == mu_min) {
					ns = retrieve_netstate(&cs->egress_addr,
							       bgp);
					if (!ns) break;
					if (ns->loss < l_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else if (ns->loss > l_min)
						continue;
					else if (ns->delay < d_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else if (ns->delay > d_min)
						continue;
					else if (ns->jitter < j_min) {
						memcpy(&eip, &cs->egress_addr,
						       sizeof(struct in6_addr));
						cu_min = cs->com_usage;
						mu_min = cs->mem_usage;
						l_min = ns->loss;
						d_min = ns->delay;
						j_min = ns->jitter;
						flag = 1;
					} else
						continue;
				} else if (cs->mem_usage > mu_min)
					continue;
			}
		}
		if (flag) {
			update_can_rib(&bgp->sid_list[i], &eip, bgp);
			cnt++;
		}
	}
	return cnt;
}

/***************************************************
 * Function name: if_sid_exist
 * Description: judge whether a SID has been stored
 * Parameters:
 * 		@sid		Target SID
 * 		@bgp		Default BGP instance
 * Return: True if stored, False if not stored
 *
 ****************************************************/
static bool if_sid_exist(struct in6_addr *sid, struct bgp *bgp)
{
	int s = bgp->sid_list_size;
	if (!s)
		return false;
	int i = 0;
	for (i = 0; i < s; i++)
		if (!memcmp(sid, &bgp->sid_list[i], sizeof(struct in6_addr)))
			return true;
	return false;
}

/***************************************************
 * Function name: update_sid_list
 * Description: store SID get from comstate advertisement in my own SID list
 * Parameters:
 * 		@sid		Target SID
 * 		@bgp		Default BGP instance
 * Return: NULL
 *
 ****************************************************/
static void update_sid_list(struct in6_addr *sid, struct bgp *bgp)
{
	int s = bgp->sid_list_size;
	if (if_sid_exist(sid, bgp))
		return;
	memcpy(&bgp->sid_list[s], sid, sizeof(struct in6_addr));
	bgp->sid_list_size++;
}

/***************************************************
 * Function name: update_net_entry
 * Description: store netstate entry into local netstate table
 * Parameters:
 * 		@bgp		Default BGP instance
 * 		@src		Source address
 * 		@dst		Destination address
 * 		@delay		Network delay or latency
 * 		@jitter		Network jitter
 * 		@loss		Packet loss rate
 * Return: number of stored netstate entries
 *
 ****************************************************/
static int update_net_entry(struct bgp *bgp, struct in6_addr src,
			    struct in6_addr dst, float delay, float jitter,
			    float loss)
{
	int s = bgp->net_table_size;
	int i = 0;
	for (i = 0; i < s; i++) {
		if (!memcmp(&(bgp->net_table_entry[i]->src_addr), &src,
			    sizeof(struct in6_addr))) {
			if (!memcmp(&(bgp->net_table_entry[i]->dest_addr), &dst,
				    sizeof(struct in6_addr))) {
				bgp->net_table_entry[i]->delay = delay;
				bgp->net_table_entry[i]->jitter = jitter;
				bgp->net_table_entry[i]->loss = loss;
				return SUCCESS_CODE;
			}
		}
	}
	bgp->net_table_entry[i] = XMALLOC(MTYPE_TMP, sizeof(struct netstate));
	bgp->net_table_entry[i]->src_addr = src;
	bgp->net_table_entry[i]->dest_addr = dst;
	bgp->net_table_entry[i]->delay = delay;
	bgp->net_table_entry[i]->jitter = jitter;
	bgp->net_table_entry[i]->loss = loss;
	bgp->net_table_size++;
	return SUCCESS_CODE;
}

/***************************************************
 * Function name: update_com_entry
 * Description: store comstate entry into local comstate table
 * Parameters:
 * 		@bgp		Default BGP instance
 * 		@sid		Servcie ID
 * 		@eip		Egress IP
 * 		@com		CPU utilization, its name is an issue left over
 *from history
 * 		@mem		Memory utilization
 * 		@pref		Preference, newest is the best
 * Return: state code
 *
 ****************************************************/
static int update_com_entry(struct bgp *bgp, struct in6_addr sid,
			    struct in6_addr eip, float com, float mem, int pref)
{
	int s = bgp->com_table_size;
	int i = 0;
	for (i = 0; i < s; i++) {
		if (!memcmp(&(bgp->com_table_entry[i]->sid_addr), &sid,
			    sizeof(struct in6_addr))
		    && !memcmp(&(bgp->com_table_entry[i]->egress_addr), &eip,
			       sizeof(struct in6_addr))) {
			if (pref > bgp->com_table_entry[i]->pref) {
				bgp->com_table_entry[i]->com_usage = com;
				bgp->com_table_entry[i]->mem_usage = mem;
				bgp->com_table_entry[i]->pref = pref;
				return SUCCESS_CODE;
			} else {
				return PASS_CODE;
			}
		}
	}
	bgp->com_table_entry[i] = XMALLOC(MTYPE_TMP, sizeof(struct comstate));
	bgp->com_table_entry[i]->sid_addr = sid;
	update_sid_list(&sid, bgp);
	bgp->com_table_entry[i]->egress_addr = eip;
	bgp->com_table_entry[i]->com_usage = com;
	bgp->com_table_entry[i]->mem_usage = mem;
	bgp->com_table_entry[i]->pref = pref;
	bgp->com_table_size++;
	return SUCCESS_CODE;
}


/***************************************************
 * Function name: deal_with_com
 * Description: deal with what we got about comstate, this is a reserved
 *interface for other possible operation Parameters:
 * 		@bgp		Default BGP instance
 * 		@sid		Servcie ID
 * 		@eip		Egress IP
 * 		@com		CPU utilization, its name is an issue left over
 *from history
 * 		@mem		Memory utilization
 * 		@pref		Preference, newest is the best
 * Return: NULL
 *
 ****************************************************/
static void deal_with_com(struct bgp *bgp, struct in6_addr sid,
			  struct in6_addr eip, float com, float mem, int pref)
{
	int ret = update_com_entry(bgp, sid, eip, com, mem, pref);

	char sid_str[INET6_ADDRSTRLEN]; 
    char eip_str[INET6_ADDRSTRLEN]; 
	inet_ntop(AF_INET6, &sid, sid_str, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &eip, eip_str, INET6_ADDRSTRLEN);

	if (ret == SUCCESS_CODE) {
		char buff[BUFFER_SIZE];
		memset(buff, 0, BUFFER_SIZE);
		char *localtime = get_local_time();
		sprintf(buff,
			"[%s] Need to advertise Comstate: SID: %s, EIP: %s, CPU usage: %.2f%%, Memory usage: %.2f%%, Preference: %d\n",
			localtime, sid_str, eip_str, com, mem, pref);
		write_log(debug_adver_log, buff, &debug_adver_log_cnt);
		XFREE(MTYPE_TMP, localtime);
		struct comstate cs;
		memcpy(&cs.sid_addr, &sid, sizeof(struct in6_addr));
		memcpy(&cs.egress_addr, &eip, sizeof(struct in6_addr));
		cs.com_usage = com;
		cs.mem_usage = mem;
		cs.pref = pref;
		com_list_insert_tail(com_list, &cs);

	} else {
		char buff[BUFFER_SIZE];
		memset(buff, 0, BUFFER_SIZE);
		char *localtime = get_local_time();
		sprintf(buff,
			"[%s][Code %d] Recieved but don't need to advertise Comstate: SID: %s, EIP: %s, CPU usage: %.2f%%, Memory usage: %.2f%%, Preference: %d\n",
			localtime, ret, sid_str, eip_str, com, mem, pref);
		write_log(debug_adver_log, buff, &debug_adver_log_cnt);
		XFREE(MTYPE_TMP, localtime);
	}
}

/***************************************************
 * Function name: socket_open_http
 * Description: establish connection with database
 * Parameters:
 * 		@bgp		Default BGP instance
 * Return: socket ID, or 0 if failed
 *
 ****************************************************/
int socket_open_http(struct bgp *bgp)
{
	int socketId;
	struct sockaddr_in serv_addr;
	int status;
	char *server_host;
	int service_port;
	if (bgp->server_nondefault) {
		server_host = bgp->server_host;
		service_port = bgp->service_port;
	} else {
		server_host = "10.99.12.102";
		bgp->server_host = "10.99.12.102";
		service_port = 3000;
		bgp->service_port = 3000;
	}
	socketId = socket(AF_INET, SOCK_STREAM, 0);
	if ((int)socketId < 0) {
		return -1;
	}
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_addr.s_addr = inet_addr(server_host);
	serv_addr.sin_port = htons(service_port); // 端口
	serv_addr.sin_family = AF_INET;
	// Connect to remote server
	status = connect(socketId, (struct sockaddr *)&serv_addr,
			 sizeof(serv_addr));
	if (status != 0) {
		close(socketId);
		return -1;
	}
	return socketId;
}

/***************************************************
 * Function name: get_local_ip
 * Description: get all local IP address
 * Parameters:
 * 		@ip		To be filled with IP address
 * Return: local IP address
 *
 ****************************************************/
char **get_local_ip(char *ip[])
{
	int n = 0;
	int fd, interface;
	struct ifreq buf[INET_ADDRSTRLEN];
	struct ifconf ifc;
	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) >= 0) {
		ifc.ifc_len = sizeof(buf);

		ifc.ifc_buf = (caddr_t)buf;
		if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {
			interface = ifc.ifc_len / sizeof(struct ifreq);
			while (interface-- > 0) {
				if (!(ioctl(fd, SIOCGIFADDR,
					    (char *)&buf[interface]))) {
					strcat(ip[n++],
					       inet_ntoa(
						       ((struct sockaddr_in
								 *)(&buf[interface]
									     .ifr_addr))
							       ->sin_addr));
				}
			}
		}
		close(fd);
	}
	return ip;
}

/***************************************************
 * Function name: get_local_ipv6
 * Description: get all local IPv6 address
 * Parameters:
 * 		@ip		To be filled with IPv6 address
 * Return: local IPv6 address
 *
 ****************************************************/
char **get_local_ipv6(char *ip[]) {
    int n = 0;
    int fd, interface;
    struct ifreq buf[INET6_ADDRSTRLEN];
    struct ifconf ifc;
	
	// 创建一个用于获取ipv6地址的套接字
    if ((fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_IP)) >= 0) {		// IPPROTO_IP = 0
        ifc.ifc_len = sizeof(buf);		// 设置 ifc 结构的缓冲区长度
        ifc.ifc_buf = (caddr_t)buf;	    // 将缓冲区指针指向 buf

        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc)) {
            interface = ifc.ifc_len / sizeof(struct ifreq);

            while (interface-- > 0) {
                if (!(ioctl(fd, SIOCGIFADDR, (char *)&buf[interface]))) {
                    ip[n] = (char *)malloc(INET6_ADDRSTRLEN);
                    if (ip[n] != NULL) {
                        inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&buf[interface].ifr_addr)->sin6_addr), ip[n], INET6_ADDRSTRLEN);
                        n++;
                    }
                }
            }
        }
        close(fd);
    }
    return ip;
}

/***************************************************
 * Function name: strrmv
 * Description: remove all chosen character from target string
 * Parameters:
 * 		@tar		Target string
 * 		@remv		Chosen character
 * Return: result string
 *
 ****************************************************/
char *strrmv(const char *tar, char remv)
{
	char *res = strdup(tar);

	int i = 0, j = 0;
	for (i = 0, j = 0; res[i] != '\0'; i++)
		if (res[i] != remv)
			res[j++] = res[i];
	res[j] = '\0';
	return res;
}

/***************************************************
 * Function name: update_netstate
 * Description: get new netstate from database
 * Parameters:
 * 		@bgp		Default BGP instance
 * Return: count of stored netstate entries
 *
 ****************************************************/
static int update_netstate(struct bgp *bgp)
{
	int cnt = 0;
	int skt_id = socket_open_http(bgp);
	if (skt_id <= 0) {
		bgp->ns_connect_established = 0;
		return 0;
	}
	bgp->ns_connect_established = 1;
	char *local_ip[MAX_INTERFACE];
	// uint32_t tmp;
	struct in6_addr src, dst;
	float delay, jitter, loss;
	for (int i = 0; i < MAX_INTERFACE; i++) {
		local_ip[i] = XMALLOC(MTYPE_TMP, INET6_ADDRSTRLEN);
		memset(local_ip[i], 0, INET6_ADDRSTRLEN);
	}
	memcpy(local_ip, get_local_ipv6(local_ip), sizeof(char *));
	char request[1000] =
		"GET /api/netstate?_fields=Source,Destination,Delay,Jitter,Loss&_where=(Source,eq,";
	strcat(request, local_ip[0]);
	strcat(request, ")");
	for (int i = 1; i < 64 && local_ip[i][0] != '\0'; i++) {
		strcat(request, "~or(Source,eq,");
		strcat(request, local_ip[i]);
		strcat(request, ")");
	}
	strcat(request, " HTTP/1.1\r\nHost:");
	strcat(request, bgp->server_host);
	strcat(request, ":");
	char port_num[10];
	int2str(bgp->service_port, port_num);
	strcat(request, port_num);
	strcat(request, "\r\n\r\n");

	write_log(debug_http_log, request, &debug_http_log_cnt);

	char tcp_buf[1600] = "";
	int send_len = send(skt_id, request, strlen(request), 0);
	if (send_len < 0) {
		return 0;
	}
	int buff_len = recv(skt_id, tcp_buf, 1600, 0);
	if (buff_len < 0) {
		return 0;
	}
	char *sep = strtok(tcp_buf, "\n");
	const char *data = "";
	while (sep) {
		if (sep[0] == '[')
			data = sep;
		sep = strtok(NULL, "\n");
	}
	struct json_object *array = json_tokener_parse(data);
	struct json_object *json_tmp = NULL;
	const char *src_str = NULL, *dst_str = NULL, *dly_str = NULL,
		   *jtr_str = NULL, *los_str = NULL;
	for (int i = 0; i < (int)json_object_array_length(array); i++) {
		json_tmp = json_object_array_get_idx(array, i);
		src_str = strrmv(
			json_object_to_json_string(
				json_object_object_get(json_tmp, "Source")),
			'"');
		dst_str = strrmv(
			json_object_to_json_string(json_object_object_get(
				json_tmp, "Destination")),
			'"');
		dly_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "Delay"));
		jtr_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "Jitter"));
		los_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "Loss"));
		
		inet_pton(AF_INET6, src_str, &src); 
        inet_pton(AF_INET6, dst_str, &dst); 
		delay = atof(dly_str);
		jitter = atof(jtr_str);
		loss = atof(los_str);
		update_net_entry(bgp, src, dst, delay, jitter, loss);

		char buffer_ns[BUFFER_SIZE];
		memset(buffer_ns, 0, BUFFER_SIZE);
		char *localtime_ns = get_local_time();
		sprintf(buffer_ns,
			"[%s] Updated Netstate: Source: %s, Destination: %s, Delay: %s, Jitter: %s, Loss: %s%%\n",
			localtime_ns, src_str, dst_str, dly_str, jtr_str,
			los_str);
		write_log(ns_log, buffer_ns, &ns_log_cnt);
		XFREE(MTYPE_TMP, localtime_ns);

		cnt++;
	}

	json_object_put(array);
	close(skt_id);
	for (int i = 0; i < MAX_INTERFACE; i++) {
		XFREE(MTYPE_TMP, local_ip[i]);
	}
	return cnt;
}

/***************************************************
 * Function name: update_comstate
 * Description: get new comstate from database
 * Parameters:
 * 		@bgp		Default BGP instance
 * Return: count of stored comstate entries
 *
 ****************************************************/
static int update_comstate(struct bgp *bgp)
{
	int cnt = 0;
	int skt_id = socket_open_http(bgp);
	if (skt_id <= 0) {
		bgp->cs_connect_established = 0;
		return 0;
	}
	bgp->cs_connect_established = 1;
	char *local_ip[MAX_INTERFACE];
	// uint32_t tmp;
	struct in6_addr sid, eip;
	float cpu, mem;
	int pref;
	for (int i = 0; i < MAX_INTERFACE; i++) {
		local_ip[i] = XMALLOC(MTYPE_TMP, INET6_ADDRSTRLEN);
		memset(local_ip[i], 0, INET6_ADDRSTRLEN);
	}
	memcpy(local_ip, get_local_ipV6(local_ip), sizeof(char *));
	char request[1000] =
		"GET /api/comstate?_fields=sid,eip,cpu_usage,memory_usage,preference&_where=(eip,eq,";
	strcat(request, local_ip[0]);
	strcat(request, ")");
	for (int i = 1; i < 64 && local_ip[i][0] != '\0'; i++) {
		strcat(request, "~or(eip,eq,");
		strcat(request, local_ip[i]);
		strcat(request, ")");
	}
	strcat(request, " HTTP/1.1\r\nHost:");
	strcat(request, bgp->server_host);
	strcat(request, ":");
	char port_num[10];
	int2str(bgp->service_port, port_num);
	strcat(request, port_num);
	strcat(request, "\r\n\r\n");

	write_log(debug_http_log, request, &debug_http_log_cnt);

	char tcp_buf[1600] = "";
	int send_len = send(skt_id, request, strlen(request), 0);
	if (send_len < 0) {
		return 0;
	}
	int buff_len = recv(skt_id, tcp_buf, 1600, 0);
	if (buff_len < 0) {
		return 0;
	}
	char *sep = strtok(tcp_buf, "\n");
	const char *data = "";
	while (sep) {
		if (sep[0] == '[')
			data = sep;
		sep = strtok(NULL, "\n");
	}
	struct json_object *array = json_tokener_parse(data);
	struct json_object *json_tmp = NULL;
	const char *sid_str = NULL, *eip_str = NULL, *cpu_str = NULL,
		   *mem_str = NULL, *pref_str = NULL;
	for (int i = 0; i < (int)json_object_array_length(array); i++) {
		json_tmp = json_object_array_get_idx(array, i);
		sid_str =
			strrmv(json_object_to_json_string(
				       json_object_object_get(json_tmp, "sid")),
			       '"');
		eip_str =
			strrmv(json_object_to_json_string(
				       json_object_object_get(json_tmp, "eip")),
			       '"');
		cpu_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "cpu_usage"));
		mem_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "memory_usage"));
		pref_str = json_object_to_json_string(
			json_object_object_get(json_tmp, "preference"));
		
		inet_pton(AF_INET6, sid_str, &sid);
		inet_pton(AF_INET6, eip_str, &eip);
		update_sid_list(&sid, bgp);
		cpu = atof(cpu_str);
		mem = atof(mem_str);
		pref = atoi(pref_str);
		deal_with_com(bgp, sid, eip, cpu, mem, pref);

		char buff[BUFFER_SIZE];
		memset(buff, 0, BUFFER_SIZE);
		char *localtime = get_local_time();
		sprintf(buff,
			"[%s] Updated Comstate: SID: %s, EIP: %s, CPU usage: %s%%, Memory usage: %s%%, Preference: %s\n",
			localtime, sid_str, eip_str, cpu_str, mem_str,
			pref_str);
		write_log(cs_upd_log, buff, &cs_upd_log_cnt);
		XFREE(MTYPE_TMP, localtime);
		cnt++;
	}

	json_object_put(array);
	close(skt_id);
	for (int i = 0; i < MAX_INTERFACE; i++) {
		XFREE(MTYPE_TMP, local_ip[i]);
	}

	return cnt;
}

/*
 * Called by bgp_attr_ext_communities().
 */
/***************************************************
 * Function name: parse_comstate
 * Description: parse what we got from comstate advertisement message
 * Parameters:
 * 		@ecom		extended community attribute with our comstate
 *info Return: NULL
 *
 ****************************************************/
void parse_comstate(struct ecommunity *ecom)
{
	struct in_addr sid;
	struct in_addr eip;
	memset(&sid, 0, sizeof(struct in_addr));
	memset(&eip, 0, sizeof(struct in_addr));
	int com_100 = 0;
	int mem_100 = 0;
	float com = 0;
	float mem = 0;
	int pref = 0;
	struct bgp *bgp;
	bgp = bgp_get_default();
	int i = 0;
	int comstate_num = 0;

	for (i = 0; i < ecom->size; i++) {
		if (ecom->val[1 + ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_SERVICE_ID) {
			comstate_num++;
			memcpy(&sid, &(ecom->val[2 + ECOMMUNITY_SIZE * i]), 4);
			continue;
		}
		if (ecom->val[1 + ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_EGRESS_IP) {
			comstate_num++;
			memcpy(&eip, &(ecom->val[2 + ECOMMUNITY_SIZE * i]), 4);
			continue;
		}
		if (ecom->val[1 + ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_COMPUTATION_USAGE) {
			comstate_num++;
			memcpy(&com_100, &(ecom->val[2 + ECOMMUNITY_SIZE * i]),
			       4);
			com = (float)(ntohl(com_100)) / 100;
			continue;
		}
		if (ecom->val[1 + ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_MEMORY_USAGE) {
			comstate_num++;
			memcpy(&mem_100, &(ecom->val[2 + ECOMMUNITY_SIZE * i]),
			       4);
			mem = (float)(ntohl(mem_100)) / 100;
			continue;
		}
		if (ecom->val[1 + ECOMMUNITY_SIZE * i] == ECOMMUNITY_ENABLED) {
			comstate_num++;
			memcpy(&pref, &(ecom->val[2 + ECOMMUNITY_SIZE * i]), 4);
			pref = ntohl(pref);
			continue;
		}
	}
	if (comstate_num > 0) {
		deal_with_com(bgp, sid, eip, com, mem, pref);
		char sid_a[32] = "";
		char eip_a[32] = "";
		strcpy(sid_a, inet_ntoa(sid));
		strcpy(eip_a, inet_ntoa(eip));
		char buff[BUFFER_SIZE];
		memset(buff, 0, BUFFER_SIZE);
		char *localtime = get_local_time();
		sprintf(buff,
			"[%s] Received Comstate Advertisement: SID: %s, EIP: %s, CPU usage: %.2f, Memory usage: %.2f, Preference: %d\n",
			localtime, sid_a, eip_a, com, mem, pref);
		write_log(cs_rcv_log, buff, &cs_rcv_log_cnt);
		XFREE(MTYPE_TMP, localtime);
	}
}

/*
 * Called by bgp_attr_ipv6_ext_communities().
 */
/***************************************************
 * Function name: parse_ipv6_comstate
 * Description: parse what we got from comstate advertisement message
 * Parameters:
 * 		@ecom		ipv6 extended community attribute with our comstate
 *info Return: NULL
 *
 ****************************************************/
void parse_ipv6_comstate(struct ecommunity *ecom)
{
	struct in6_addr sid;
	struct in6_addr eip;
	memset(&sid, 0, sizeof(struct in6_addr));
	memset(&eip, 0, sizeof(struct in6_addr));
	int com_100 = 0;
	int mem_100 = 0;
	float com = 0;
	float mem = 0;
	int pref = 0;
	struct bgp *bgp;
	bgp = bgp_get_default();
	int i = 0;
	int comstate_num = 0;

	for (i = 0; i < ecom->size; i++) {
		if (ecom->val[1 + IPV6_ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_SERVICE_ID) {
			comstate_num++;
			memcpy(&sid, &(ecom->val[2 + IPV6_ECOMMUNITY_SIZE * i]), sizeof(struct in6_addr));
			continue;
		}
		if (ecom->val[1 + IPV6_ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_EGRESS_IP) {
			comstate_num++;
			memcpy(&eip, &(ecom->val[2 + IPV6_ECOMMUNITY_SIZE * i]), sizeof(struct in6_addr));
			continue;
		}
		if (ecom->val[1 + IPV6_ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_COMPUTATION_USAGE) {
			comstate_num++;
			memcpy(&com_100, &(ecom->val[2 + IPV6_ECOMMUNITY_SIZE * i]), 4);
			com = (float)(ntohl(com_100)) / 100;
			continue;
		}
		if (ecom->val[1 + IPV6_ECOMMUNITY_SIZE * i]
		    == ECOMMUNITY_MEMORY_USAGE) {
			comstate_num++;
			memcpy(&mem_100, &(ecom->val[2 + IPV6_ECOMMUNITY_SIZE * i]), 4);
			mem = (float)(ntohl(mem_100)) / 100;
			continue;
		}
		if (ecom->val[1 + IPV6_ECOMMUNITY_SIZE * i] == ECOMMUNITY_ENABLED) {
			comstate_num++;
			memcpy(&pref, &(ecom->val[2 + IPV6_ECOMMUNITY_SIZE * i]), 4);
			pref = ntohl(pref);
			continue;
		}
	}
	if (comstate_num > 0) {
		deal_with_com(bgp, sid, eip, com, mem, pref);
		char sid_a[INET6_ADDRSTRLEN] = "";
		char eip_a[INET6_ADDRSTRLEN] = "";
		inet_ntop(AF_INET6, &sid, sid_a, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &eip, eip_a, INET6_ADDRSTRLEN);
		char buff[BUFFER_SIZE];
		memset(buff, 0, BUFFER_SIZE);
		char *localtime = get_local_time();
		sprintf(buff,
			"[%s] Received Comstate Advertisement: SID: %s, EIP: %s, CPU usage: %.2f, Memory usage: %.2f, Preference: %d\n",
			localtime, sid_a, eip_a, com, mem, pref);
		write_log(cs_rcv_log, buff, &cs_rcv_log_cnt);
		XFREE(MTYPE_TMP, localtime);
	}
}


/**
 * Format convertion func.
 */
/***************************************************
 * Function name: int2str
 * Description: convert integer to string
 * Parameters:
 * 		@num		target integer data
 * 		@str		result to be filled
 * Return: NULL
 *
 ****************************************************/
void int2str(int num, char *str)
{
	int remain = 0, n = 0;
	char c;
	int i = 0;
	while (1) {
		remain = num % 10;
		str[n] = remain + '0';
		n++;
		num = (num - remain) / 10;
		if (num == 0)
			break;
	}
	for (i = 0; i < n / 2; i++) {
		c = str[i];		 //赋值给char c
		str[i] = str[n - i - 1]; // 一共n个字符
		str[n - i - 1] = c;
	}
	str[n] = '\0'; // 字符串结束标识符
}

/***************************************************
 * Function name: float2ip_str
 * Description: convert float to ip-formated string
 * Parameters:
 * 		@num		target float data
 * Return: result string
 *
 ****************************************************/
char *float2ip_str(float num)
{
	int num_100 = num * 100;
	int remain = 0;
	char c[4][6] = {{"0"}, {"0"}, {"0"}, {"0"}};
	char *str = XMALLOC(MTYPE_TMP, sizeof(char) * 32);
	memset(str, 0, 32);
	int i = 0;
	for (i = 0; i < 4; i++) {
		remain = num_100 % 256;
		num_100 = (num_100 - remain) / 256;
		int2str(remain, c[i]);
		if (num_100 == 0)
			break;
	}
	for (i = 3; i >= 0; i--) {
		strcat(str, c[i]);
		if (i > 0)
			strcat(str, ".");
	}
	return str;
}

/**
 * Copy from bgp.packet.c, for the original function is static so that cannot be
 * refered in other file
 */
static void bgp_packet_add(struct peer_connection *connection,
			   struct peer *peer, struct stream *s)
{
	intmax_t delta;
	uint32_t holdtime;
	intmax_t sendholdtime;

	frr_with_mutex (&connection->io_mtx) {
		/* if the queue is empty, reset the "last OK" timestamp to
		 * now, otherwise if we write another packet immediately
		 * after it'll get confused
		 */
		if (!stream_fifo_count_safe(connection->obuf))
			peer->last_sendq_ok = monotime(NULL);

		stream_fifo_push(connection->obuf, s);

		delta = monotime(NULL) - peer->last_sendq_ok;

		if (CHECK_FLAG(peer->flags, PEER_FLAG_TIMER))
			holdtime = atomic_load_explicit(&peer->holdtime,
							memory_order_relaxed);
		else
			holdtime = peer->bgp->default_holdtime;

		sendholdtime = holdtime * 2;

		/* Note that when we're here, we're adding some packet to the
		 * OutQ.  That includes keepalives when there is nothing to
		 * do, so there's a guarantee we pass by here once in a while.
		 *
		 * That implies there is no need to go set up another separate
		 * timer that ticks down SendHoldTime, as we'll be here sooner
		 * or later anyway and will see the checks below failing.
		 */
		if (!holdtime) {
			/* no holdtime, do nothing. */
		} else if (delta > sendholdtime) {
			flog_err(
				EC_BGP_SENDQ_STUCK_PROPER,
				"%pBP has not made any SendQ progress for 2 holdtimes (%jds), terminating session",
				peer, sendholdtime);
			bgp_stop_with_notify(connection,
					     BGP_NOTIFY_SEND_HOLD_ERR, 0);
		} else if (delta > (intmax_t)holdtime &&
			   monotime(NULL) - peer->last_sendq_warn > 5) {
			flog_warn(
				EC_BGP_SENDQ_STUCK_WARN,
				"%pBP has not made any SendQ progress for 1 holdtime (%us), peer overloaded?",
				peer, holdtime);
			peer->last_sendq_warn = monotime(NULL);
		}
	}
}

/**
 * Generate advertisement packet and send it out, bingo!
 */
/***************************************************
 * Function name: bgp_can_send_comstate_adver
 * Description: advertise single comstate information to single bgp peer, used
 * with function hash_iterate 
 * Parameters:
 * 		@peer_can		Pointer to peer and comstate
 * Return: NULL
 *
 ****************************************************/
static void bgp_can_send_comstate_adver(struct peer_can *peer_can)
{
	struct stream *s;
	struct peer *peer = peer_can->peer;
	struct comstate *entry = com_list->head->next->entry;

	uint32_t tmp = 0;

	s = stream_new(BGP_STANDARD_MESSAGE_MAX_PACKET_SIZE);

	/* Make keepalive packet. */
	bgp_packet_set_marker(s, BGP_MSG_UPDATE);

	/* Set withdrawn routes length = 0 */
	stream_putw(s, 0);

	/* Set total path attribute length = 131 */
	stream_putw(s, 0x0083);

	/* Set origin attribute */
	/* Flag = 0x40,  Type code = 1(Origin), Length = 1, Origin = 0(IGP)*/
	stream_putl(s, 0x40010100);

	/* Set as_path attribute */
	/* Flag = 0x50, Type code = 2(As_path), Length =  6*/
	stream_putl(s, 0x50020006);
	/* Segment type = AS_SEQUENCE(2), number of ASN = 1 */
	stream_putw(s, 0x0201);
	/* AS4 = 4294967295(MAX) */
	stream_putl(s, 0xffffffff);

	/* Set next_hop attribute */
	/* Flag = 0x40, Type code = 3(Next hop), Length = 4 */
	stream_put3(s, 0x400304);
	/* nexthop: 172.255.255.255 */
	stream_putl(s, 0xacffffff);

	/* Set local_pref attribute */
	/* Flag = 0x40, Type code = 5(Local_pref), Length = 4 */
	stream_put3(s, 0x400504);
	/* local_pref = 0xffffffff */
	stream_putl(s, 0xffffffff);

	/* Set comstate info(extcommunity) attribute */
	/* Flag = 0xc0, Type code = 16(Extended community), Length = 100(5 entry * 20 bytes) */
	
	// stream_put3(s, 0xc01028);
	stream_put3(s, 0xc01064);

	/* Entry 1 sid */
	stream_putw(s, 0x0111);
	for(int i=0; i<16; i++){
		stream_putc(s, entry->sid_addr.s6_addr[i]);
	}
	stream_putw(s, 0);		// Padding to make up 20 bytes (remaining 4 bytes)

	/* Entry 2 eip */
	stream_putw(s, 0x0113);
	for(int i=0; i<16; i++){
		stream_putc(s, entry->egress_addr.s6_addr[i]);
	}
	stream_putw(s, 0);		// Padding to make up 20 bytes (remaining 4 bytes)

	/* Entry 3 com_usage */
	stream_putw(s, 0x0114);
	tmp = inet_addr(float2ip_str(entry->com_usage));
	tmp = htonl(tmp);
	stream_putl(s, tmp);
	for(int i=0; i<20-6; i++){	// Padding to make up 20 bytes 
		stream_putc(s, 0);
	}

	/* Entry 4 mem_usage */
	stream_putw(s, 0x0115);
	tmp = inet_addr(float2ip_str(entry->mem_usage));
	tmp = htonl(tmp);
	stream_putl(s, tmp);
	for(int i=0; i<20-6; i++){	// Padding to make up 20 bytes 
		stream_putc(s, 0);
	}

	/* Entry 5 pref */
	stream_putw(s, 0x0116);
	tmp = entry->pref;
	stream_putl(s, tmp);
	for(int i=0; i<20-6; i++){	// Padding to make up 20 bytes 
		stream_putc(s, 0);
	}

	/* Set NLRI with SID*/
	stream_putc(s, 0x20);
	stream_putl(s, 0xacffffff);

	/* Set packet size. */
	bgp_packet_set_size(s);

	bgp_packet_add(peer->connection, peer, s);

	bgp_writes_on(peer->connection);

	char sid[INET6_ADDRSTRLEN] = "";
	char eip[INET6_ADDRSTRLEN] = "";
	inet_ntop(AF_INET6, &(entry->sid_addr), sid, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(entry->egress_addr), eip, INET6_ADDRSTRLEN);

	char buff[BUFFER_SIZE];
	memset(buff, 0, BUFFER_SIZE);
	char *localtime = get_local_time();
	sprintf(buff,
		"[%s] Sended Comstate Advertisement: SID: %s, EIP: %s, CPU usage: %.2f, Memory usage: %.2f, Preference: %d\n",
		localtime, sid, eip, entry->com_usage, entry->mem_usage,
		entry->pref);
	write_log(cs_snd_log, buff, &cs_snd_log_cnt);
	XFREE(MTYPE_TMP, localtime);
}

/**
 * This part defines can_pthread, responsible for send advertisement, get
 * comstate and netstate from remote. Try not to change them.
 */
/***************************************************
 * Function name: process_can_advertise
 * Description: relevant timer or sth
 * Parameters:
 * 		@bgp		Default BGP instance
 * Return: NULL
 *
 ****************************************************/
static void process_can_update(struct bgp *bgp)
{
	static struct timeval elapsed_nu; // elapsed time since advertise
	static struct timeval elapsed_cu; // elapsed time since update
	static struct timeval nu = {0};	  // netstate_update as a timeval
	static struct timeval cu = {0};	  // comstate_update as a timeval
	static struct timeval diff_nu;	  // nu - elapsed_nu
	static struct timeval diff_cu;	  // cu - elapsed_cu

	static const struct timeval tolerance = {0, 100000};

	monotime_since(&last_netstate_update, &elapsed_nu);
	monotime_since(&last_comstate_update, &elapsed_cu);
	nu.tv_sec = bgp->default_can_advertise;
	cu.tv_sec = bgp->default_can_advertise;
	timersub(&nu, &elapsed_nu, &diff_nu);
	timersub(&cu, &elapsed_cu, &diff_cu);

	int netstate_update = elapsed_nu.tv_sec >= nu.tv_sec
			      || timercmp(&diff_nu, &tolerance, <);

	int comstate_update = elapsed_cu.tv_sec >= cu.tv_sec
			      || timercmp(&diff_cu, &tolerance, <);

	if (netstate_update
	    && bgp->can_type_code == CAN_ROUTER_TYPE_INGRESS_NODE) {
		update_netstate(bgp);
		path_calculation(bgp);
		if (bgp->can_rib_size)
		 	write_rib(bgp);
		monotime(&last_netstate_update);
		memset(&elapsed_nu, 0x00, sizeof(struct timeval));
		diff_nu = nu;
	}
	if (comstate_update
	    && bgp->can_type_code == CAN_ROUTER_TYPE_EGRESS_NODE) {
		update_comstate(bgp);
		monotime(&last_comstate_update);
		memset(&elapsed_cu, 0x00, sizeof(struct timeval));
		diff_cu = cu;
	}
}

static void process_can_advertise(struct hash_bucket *hb, void *arg)
{
	struct peer_can *peer_can = hb->data;
	bgp_can_send_comstate_adver(peer_can);
}

/* Cleanup handler / deinitializer. */
static void bgp_can_adver_finish(void *arg)
{
	if (peerhash_can) {
		hash_clean(peerhash_can, peer_can_del);
		hash_free(peerhash_can);
	}

	peerhash_can = NULL;

	pthread_mutex_unlock(peerhash_can_mtx);
	pthread_mutex_destroy(peerhash_can_mtx);
	pthread_cond_destroy(peerhash_can_cond);

	XFREE(MTYPE_TMP, peerhash_can_mtx);
	XFREE(MTYPE_TMP, peerhash_can_cond);
}
/*
 * Entry function for peer can generation pthread.
 */
/***************************************************
 * Function name: bgp_can_advertise_start
 * Description: pthread start function
 * Parameters:
 * 		@arg		Argument
 * Return: NULL
 *
 ****************************************************/
void *bgp_can_advertise_start(void *arg)
{
	struct frr_pthread *fpt = arg;
	fpt->master->owner = pthread_self();

	struct timespec wait_ts = {1, 0};

	peerhash_can_mtx = XCALLOC(MTYPE_TMP, sizeof(pthread_mutex_t));
	peerhash_can_cond = XCALLOC(MTYPE_TMP, sizeof(pthread_cond_t));

	com_list_mtx = XCALLOC(MTYPE_TMP, sizeof(pthread_mutex_t));

	char mtx_addr[100];
	memset(mtx_addr, 0, 100);
	sprintf(mtx_addr, "peerhash_can_mtx located in [%p]\n", peerhash_can_mtx);
	write_log(debug_mtx_log, mtx_addr, &debug_mtx_log_cnt);
	memset(mtx_addr, 0, 100);
	sprintf(mtx_addr, "com_list_mtx located in [%p]\n", com_list_mtx);
	write_log(debug_mtx_log, mtx_addr, &debug_mtx_log_cnt);

	/* Initialize mutex */
	pthread_mutex_init(peerhash_can_mtx, NULL);
	pthread_mutex_init(com_list_mtx, NULL);

	com_list = com_list_new();
	com_list_size = 0;

	/* Condition variable */
	pthread_condattr_t attrs_can;
	pthread_condattr_init(&attrs_can);
	pthread_condattr_setclock(&attrs_can, CLOCK_MONOTONIC);
	pthread_cond_init(peerhash_can_cond, &attrs_can);
	pthread_condattr_destroy(&attrs_can);

	/*
	 * We are not using normal FRR pthread mechanics and are
	 * not using fpt_run
	 */
	frr_pthread_set_name(fpt);

	/* initialize peer hashtable */
	peerhash_can = hash_create_size(2048, peer_hash_can_key,
					peer_hash_can_cmp, NULL);
	pthread_mutex_lock(peerhash_can_mtx);

	/* register cleanup handler */
	pthread_cleanup_push(&bgp_can_adver_finish, NULL);

	/* notify anybody waiting on us that we are done starting up */
	frr_pthread_notify_running(fpt);

	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		if (peerhash_can->count > 0)
			pthread_cond_timedwait(peerhash_can_cond, peerhash_can_mtx,
					       &wait_ts);
		else
			while (peerhash_can->count == 0 && atomic_load_explicit(&fpt->running, memory_order_relaxed))
				pthread_cond_wait(peerhash_can_cond, peerhash_can_mtx);
		// bgp = bgp_get_default();
		sleep(0);
		while (com_list_size) {
			frr_with_mutex (com_list_mtx) {
				hash_iterate(peerhash_can, process_can_advertise, NULL);
			}
			com_list_remove_head(com_list);
		}
	}
	/* clean up */
	pthread_cleanup_pop(1);
	return NULL;
}

/* -------------------- thread external functions -------------------- */
void bgp_can_advertise_on(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (CHECK_FLAG(peer->thread_flags, PEER_THREAD_CAN_ADVER_ON))
		return;

	struct frr_pthread *fpt = bgp_pth_can_advertise;
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct peer_can holder = {0};

	/*
	 * We need to ensure that bgp_keepalives_init was called first
	 */
	assert(peerhash_can_mtx);

	frr_with_mutex (peerhash_can_mtx) {
		holder.peer = peer;
		if (!hash_lookup(peerhash_can, &holder)) {
			struct peer_can *peer_can = peer_can_new(peer);
			hash_get(peerhash_can, peer_can, hash_alloc_intern);
			peer_lock(peer);
		}
		SET_FLAG(peer->thread_flags, PEER_THREAD_CAN_ADVER_ON);
	}
	bgp_can_advertise_wake();
}

void bgp_can_advertise_off(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (!CHECK_FLAG(peer->thread_flags, PEER_THREAD_CAN_ADVER_ON))
		return;

	struct frr_pthread *fpt = bgp_pth_can_advertise;
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct peer_can holder = {0};

	/*
	 * We need to ensure that bgp_keepalives_init was called first
	 */
	assert(peerhash_can_mtx);

	frr_with_mutex (peerhash_can_mtx) {
		holder.peer = peer;
		struct peer_can *res = hash_release(peerhash_can, &holder);
		if (res) {
			peer_can_del(res);
			peer_unlock(peer);
		}
		UNSET_FLAG(peer->thread_flags, PEER_THREAD_CAN_ADVER_ON);
	}
}

void bgp_can_advertise_wake(void)
{
	frr_with_mutex (peerhash_can_mtx) {
		pthread_cond_signal(peerhash_can_cond);
	}
}

/***************************************************
 * Function name: bgp_can_advertise_stop
 * Description: pthread terminate function
 * Parameters:
 * 		@fpt		Target pthread
 * 		@result		Function execution result
 * Return: 0 if success
 *
 ****************************************************/
int bgp_can_advertise_stop(struct frr_pthread *fpt, void **result)
{
	assert(fpt->running);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	bgp_can_advertise_wake();

	pthread_join(fpt->thread, result);
	return 0;
}

/* -------------------- update thread external functions -------------------- */
void *bgp_can_update_start(void *arg)
{
	struct frr_pthread *fpt = arg;
	fpt->master->owner = pthread_self();

	struct bgp *bgp;

	monotime(&last_netstate_update);
	monotime(&last_comstate_update);

	/*
	 * We are not using normal FRR pthread mechanics and are
	 * not using fpt_run
	 */
	frr_pthread_set_name(fpt);


	/* notify anybody waiting on us that we are done starting up */
	frr_pthread_notify_running(fpt);

	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		bgp = bgp_get_default();
		sleep(1);
		if (!bgp)
			continue;

		process_can_update(bgp);
	}
	return NULL;
}

int bgp_can_update_stop(struct frr_pthread *fpt, void **result)
{
	assert(fpt->running);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);

	pthread_join(fpt->thread, result);
	return 0;
}
