/*
 * nss-dontstalkme: Return localhost for tracking host IPs
 *
 * Copyright (C) 2014 Guido Günther
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Author: Guido Günther <agx@sigxcpu.org>
 *
 * Heavily inspired by nss-myhostname.c which is
 * Copyright 2008-2011 Lennart Poettering
 */

#include <assert.h>
#include <nss.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <errno.h>
#include <net/if.h>

/* We use 127.0.2.1 as returned address */
#define LOCALADDRESS_IPV4 (htonl(0x7F000201))
#define LOCALADDRESS_IPV6 &in6addr_loopback
#define LOOPBACK_INTERFACE "lo"

#define ALIGN(a) (((a+sizeof(void*)-1)/sizeof(void*))*sizeof(void*))
#define _public_ __attribute__ ((visibility("default")))
#define ARRAY_CARDINALITY(Array) (sizeof(Array) / sizeof(*(Array)))

/*
   The hosts we blacklist
   To blacklist all hosts from domain foo.bar use .foo.bar
 */
const char* stalkers[] =  { /* https://support.google.com/analytics/answer/1009688?hl=en-GB */
                            ".google-analytics.com",
                            ".doubleclick.net",
                            "partner.googleadservices.com",
                            "p.twitter.com",
                          };

enum nss_status _nss_dontstalkme_gethostbyname4_r(const char *name,
                                                  struct gaih_addrtuple **pat,
                                                  char *buffer, size_t buflen,
                                                  int *errnop, int *h_errnop,
                                                  int32_t *ttlp) _public_;

enum nss_status _nss_dontstalkme_gethostbyname3_r(const char *name,
                                                  int af,
                                                  struct hostent *host,
                                                  char *buffer, size_t buflen,
                                                  int *errnop, int *h_errnop,
                                                  int32_t *ttlp,
                                                  char **canonp) _public_;

enum nss_status _nss_dontstalkme_gethostbyname2_r(const char *name,
                                                  int af,
                                                  struct hostent *host,
                                                  char *buffer, size_t buflen,
                                                  int *errnop, int *h_errnop) _public_;

enum nss_status _nss_dontstalkme_gethostbyname_r(const char *name,
                                                 struct hostent *host,
                                                 char *buffer, size_t buflen,
                                                 int *errnop, int *h_errnop) _public_;


/*
 * check if host matches the given pattern.
 *
 * If pattern starts with a dot all names ending in pattern will
 * match. Otherwise name has to match pattern exactly.
*/
static int
match_pattern (const char *name, const char *pattern)
{
    int name_len = strlen(name);
    int pattern_len = strlen(pattern);

    if (pattern_len && pattern[0] == '.') {
        if (name_len < pattern_len)
            return 0;

        return strcmp (name + name_len - pattern_len, pattern) == 0;
    } else {
        if (!strcasecmp(name, pattern))
            return 1;
    }
    return 0;
}


static int
is_stalker (const char* name)
{
    unsigned int i = 0;

    for (i = 0; i < ARRAY_CARDINALITY(stalkers); i++) {
        if (match_pattern(name, stalkers[i]))
            return 1;
    }
    return 0;
}


enum nss_status
_nss_dontstalkme_gethostbyname4_r(const char *name,
                                 struct gaih_addrtuple **pat,
                                 char *buffer, size_t buflen,
                                 int *errnop, int *h_errnop,
                                 int32_t *ttlp)
{
    unsigned lo_ifi;
    size_t l, idx, ms;
    char *r_name;
    struct gaih_addrtuple *r_tuple, *r_tuple_prev = NULL;

    lo_ifi = if_nametoindex(LOOPBACK_INTERFACE);

    if (! is_stalker(name)) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    l = strlen(name);
    ms = ALIGN(l+1)+ALIGN(sizeof(struct gaih_addrtuple))*2;
    if (buflen < ms) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* First, fill in hostname */
    r_name = buffer;
    l = strlen(name);
    memcpy(r_name, name, l+1);
    idx = ALIGN(l+1);

    /* Second, fill in IPv6 tuple */
    r_tuple = (struct gaih_addrtuple*) (buffer + idx);
    r_tuple->next = r_tuple_prev;
    r_tuple->name = r_name;
    r_tuple->family = AF_INET6;
    memcpy(r_tuple->addr, LOCALADDRESS_IPV6, 16);
    r_tuple->scopeid = (uint32_t) lo_ifi;

    idx += ALIGN(sizeof(struct gaih_addrtuple));
    r_tuple_prev = r_tuple;

    /* Third, fill in IPv4 tuple */
    r_tuple = (struct gaih_addrtuple*) (buffer + idx);
    r_tuple->next = r_tuple_prev;
    r_tuple->name = r_name;
    r_tuple->family = AF_INET;
    *(uint32_t*) r_tuple->addr = LOCALADDRESS_IPV4;
    r_tuple->scopeid = (uint32_t) lo_ifi;

    idx += ALIGN(sizeof(struct gaih_addrtuple));
    r_tuple_prev = r_tuple;

    /* Verify the size matches */
    assert(idx == ms);

    *pat = r_tuple_prev;

    if (ttlp)
        *ttlp = 0;

    return NSS_STATUS_SUCCESS;
}

static inline size_t
proto_address_size(int proto)
{
    assert(proto == AF_INET || proto == AF_INET6);
    return proto == AF_INET6 ? 16 : 4;
}

static enum nss_status
fill_in_hostent(const char *hn,
                int af,
                struct hostent *result,
                char *buffer, size_t buflen,
                int *errnop, int *h_errnop,
                int32_t *ttlp,
                char **canonp)
{

    size_t l, idx, ms;
    char *r_addr, *r_name, *r_aliases, *r_addr_list;
    size_t alen;

    alen = proto_address_size(af);

    l = strlen(hn);
    ms = ALIGN(l+1)+
        sizeof(char*)+
        ALIGN(alen)+
        2*sizeof(char*);

    if (buflen < ms) {
        *errnop = ENOMEM;
        *h_errnop = NO_RECOVERY;
        return NSS_STATUS_TRYAGAIN;
    }

    /* First, fill in hostname */
    r_name = buffer;
    memcpy(r_name, hn, l+1);
    idx = ALIGN(l+1);

    /* Second, create (empty) aliases array */
    r_aliases = buffer + idx;
    *(char**) r_aliases = NULL;
    idx += sizeof(char*);

    /* Third, add addresses */
    r_addr = buffer + idx;
    if (af == AF_INET)
        *(uint32_t*) r_addr = LOCALADDRESS_IPV4;
    else
        memcpy(r_addr, LOCALADDRESS_IPV6, 16);

    idx += ALIGN(alen);

    /* Fourth, add address pointer array */
    r_addr_list = buffer + idx;
    ((char**) r_addr_list)[0] = r_addr;
    ((char**) r_addr_list)[1] = NULL;
    idx += 2*sizeof(char*);

    /* Verify the size matches */
    assert(idx == ms);

    result->h_name = r_name;
    result->h_aliases = (char**) r_aliases;
    result->h_addrtype = af;
    result->h_length = alen;
    result->h_addr_list = (char**) r_addr_list;

    if (ttlp)
        *ttlp = 0;

    if (canonp)
        *canonp = r_name;

    return NSS_STATUS_SUCCESS;
}


enum nss_status
_nss_dontstalkme_gethostbyname3_r(const char *name,
                                 int af,
                                 struct hostent *host,
                                 char *buffer, size_t buflen,
                                 int *errnop, int *h_errnop,
                                 int32_t *ttlp,
                                 char **canonp)
{
    if (af == AF_UNSPEC)
        af = AF_INET;

    if (af != AF_INET && af != AF_INET6) {
        *errnop = EAFNOSUPPORT;
        *h_errnop = NO_DATA;
        return NSS_STATUS_UNAVAIL;
    }

    if (! is_stalker(name)) {
        *errnop = ENOENT;
        *h_errnop = HOST_NOT_FOUND;
        return NSS_STATUS_NOTFOUND;
    }

    return fill_in_hostent(name, af, host, buffer, buflen, errnop, h_errnop, ttlp, canonp);
}


enum nss_status
_nss_dontstalkme_gethostbyname2_r(const char *name,
                                 int af,
                                 struct hostent *host,
                                 char *buffer, size_t buflen,
                                 int *errnop, int *h_errnop)
{
    return _nss_dontstalkme_gethostbyname3_r(name,
                                            af,
                                            host,
                                            buffer, buflen,
                                            errnop, h_errnop,
                                            NULL,
                                            NULL);
}


enum nss_status
 _nss_dontstalkme_gethostbyname_r(const char *name,
                                 struct hostent *host,
                                 char *buffer, size_t buflen,
                                 int *errnop, int *h_errnop)
{
    return _nss_dontstalkme_gethostbyname3_r(name,
                                            AF_UNSPEC,
                                            host,
                                            buffer, buflen,
                                            errnop, h_errnop,
                                            NULL,
                                            NULL);
}
