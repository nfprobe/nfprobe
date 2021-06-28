#ifndef __LINUX_TYPE_MAPPER_H__
#define __LINUX_TYPE_MAPPER_H__

typedef char __s8;
typedef short __s16;
typedef int __s32;
typedef long __s64;

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long __u64;

typedef char s8;
typedef short s16;
typedef int s32;
typedef long s64;

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long u64;

typedef __u64 __be64;
typedef __u32 __be32;
typedef __u16 __be16;

typedef __u64 __le64;
typedef __u32 __le32;
typedef __u16 __le16;

typedef __u64 __aligned_u64;
typedef __u16 __sum16;

typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;

#endif
