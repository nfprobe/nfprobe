#ifndef _CONFIG_H
#define _CONFIG_H

extern u32 config_ifindex;
extern u32 config_direction;
extern u64 config_bucket_width;
/*
#define c_ifindex	((u32)&config_ifindex)
#define c_direction	((u32)&config_direction)
#define c_bucket_width	((u64)&config_bucket_width)
*/

#define c_ifindex	0
#define c_direction	0
#define c_bucket_width	60*1000*1000*1000L

#endif
