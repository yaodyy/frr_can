/*********************************************
 * @File name: bgp_can.h
 * @Author: ydy, fy
 * @Version: 1.0
 * @Date: 2024-4-19
 * @Description: Macro definition, function declaration, structrue definition, blah blah
 * @Copyright: © 2024 BUPT. All rights reserved.
 **********************************************/

#ifndef _FRR_BGP_CAN_H
#define _FRR_BGP_CAN_H

#include <arpa/inet.h>
#include <math.h>

#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"

/* for bgp_ecommunity.h */
#define ECOMMUNITY_SERVICE_ID				0x11
#define ECOMMUNITY_EGRESS_IP				0x13
#define ECOMMUNITY_COMPUTATION_USAGE		0x14
#define ECOMMUNITY_MEMORY_USAGE				0x15
#define ECOMMUNITY_ENABLED					0x16

/* for bgpd.c */
#define  BGP_DEFAULT_CAN_ADVERTISE          10

/* CAN type identification code */
#define CAN_ROUTER_TYPE_INTERMIDIATE		0
#define CAN_ROUTER_TYPE_INGRESS_NODE		1
#define	CAN_ROUTER_TYPE_EGRESS_NODE			2

#define MAX_INTERFACE                       100

#define BUFFER_SIZE                         1024

#define LOG_MAX_ROW                         1000

#define TCP_BUFFSIZE                        1460

struct bgp;

struct com_node {
	struct comstate *entry;
	struct com_node *next, *pre;
};

struct com_list {
	struct com_node *head, *tail;
};

struct peer_can {
	/* the peer to send advertisement to */
	struct peer *peer;
};

/* Comstate content, may change in future */
struct comstate
{
	struct in_addr	sid_addr;		/* 服务ID，以任播地址标识 */
	struct in_addr 	egress_addr; 	/* 算力路由出口节点IP地址 */
	float 			com_usage;      /* 计算服务节点CPU/GPU/FPGA使用率 */
	float 			mem_usage;		/* 计算服务节点内存使用率 */
	int 			pref;		    /* 优先级 */
};

/* Netstate content */
struct netstate
{
    struct in_addr  src_addr;	/* 源IP地址 */
    struct in_addr  dest_addr;  /* 目的IP地址 */
    float 			delay;      /* 时延 */
    float 			jitter;     /* 时延抖动 */
    float 			loss;       /* 丢包率 */
};

/* CAN routing information base */
struct can_rib
{
    struct in_addr sid;     /* 服务ID */
    struct in_addr eip;		/* Egress IP */ 
}; 


void write_log(const char *file, char *text, int *row_cnt);
char **get_local_ip(char *ip[]);
char *strrmv(const char *tar, char remv);
void parse_comstate(struct ecommunity *ecom);
void int2str(int num, char *str);
char *float2ip_str(float num);

void *bgp_can_advertise_start(void *arg);
void bgp_can_advertise_on(struct peer_connection *peer);
void bgp_can_advertise_off(struct peer_connection *peer);
void bgp_can_advertise_wake(void);
int bgp_can_advertise_stop(struct frr_pthread *fpt, void **result);
void *bgp_can_update_start(void *arg);
int bgp_can_update_stop(struct frr_pthread *fpt, void **result);


#endif