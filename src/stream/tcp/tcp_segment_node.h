//--------------------------------------------------------------------------
// Copyright (C) 2014-2023 Cisco and/or its affiliates. All rights reserved.
//
// This program is free software; you can redistribute it and/or modify it
// under the terms of the GNU General Public License Version 2 as published
// by the Free Software Foundation.  You may not use, modify or distribute
// this program under any other version of the GNU General Public License.
//
// This program is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//--------------------------------------------------------------------------

// tcp_segment_node.h author davis mcpherson <davmcphe@cisco.com>
// Created on: Sep 21, 2015

#ifndef TCP_SEGMENT_H
#define TCP_SEGMENT_H

#include "tcp_segment_descriptor.h"
#include "tcp_defs.h"

class TcpSegmentDescriptor;

//-----------------------------------------------------------------
// we make a lot of TcpSegments so it is organized by member
// size/alignment requirements to minimize unused space
// ... however, use of padding below is critical, adjust if needed
// and we use the struct hack to avoid 2 allocs per node
//-----------------------------------------------------------------

class TcpSegmentNode
{
private:
    static TcpSegmentNode* create(const struct timeval& tv, const uint8_t* segment, uint16_t len);

public:
    static TcpSegmentNode* init(const TcpSegmentDescriptor&);
    static TcpSegmentNode* init(TcpSegmentNode&);

    void term();

    static void setup();
    static void clear();

    bool is_retransmit(const uint8_t*, uint16_t size, uint32_t, uint16_t, bool*);

    uint8_t* payload()
    { return data + offset; }

    bool is_packet_missing(uint32_t to_seq)
    {
        if ( next )
            return (i_seq + i_len) != next->i_seq;
        else
            return (c_seq + c_len) < to_seq;
    }

    void update_ressembly_lengths(uint16_t bytes)
    {
        c_seq += bytes;
        c_len -= bytes;
        offset += bytes;
    }

public:
    TcpSegmentNode* prev;
    TcpSegmentNode* next;

    struct timeval tv;
    uint32_t ts;
    uint32_t i_seq;             // initial seq # of the data segment
    uint32_t c_seq;             // current seq # of data for reassembly
    uint16_t i_len;             // initial length of the data segment
    uint16_t c_len;             // length of data remaining for reassembly
    uint16_t offset;
    uint16_t size;              // actual allocated size (overlaps cause i_len to differ)
    uint8_t data[1];
};

/* snort 重组策略, 即 Sturges/Novak 模型 《Target-Based Fragmentation Reassembly》
 * 流重组分为重组和排出（flush）两个阶段。
 * 重组阶段，根据重组策略将报文段裁剪后插入 StreamTracker->seglist 链表中；
 * 排出阶段，根据 flush 策略对 seglist 链表中的报文进行排出。
 */
class TcpSegmentList
{
public:
    uint32_t reset()
    {
        int i = 0;

        while ( head )
        {
            i++;
            TcpSegmentNode* dump_me = head;
            head = head->next;
            dump_me->term();
        }

        head = tail = cur_rseg = cur_sseg = nullptr;
        count = 0;
        return i;
    }

    void insert(TcpSegmentNode* prev, TcpSegmentNode* ss)
    {
        if ( prev )
        {
            ss->next = prev->next;
            ss->prev = prev;
            prev->next = ss;

            if ( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
        }
        else
        {
            ss->next = head;

            if ( ss->next )
                ss->next->prev = ss;
            else
                tail = ss;
            head = ss;
        }

        count++;
    }

    void remove(TcpSegmentNode* ss)
    {
        if ( ss->prev )
            ss->prev->next = ss->next;
        else
            head = ss->next;

        if ( ss->next )
            ss->next->prev = ss->prev;
        else
            tail = ss->prev;

        count--;
    }

    TcpSegmentNode* head = nullptr;
    TcpSegmentNode* tail = nullptr;
    TcpSegmentNode* cur_rseg = nullptr;
    TcpSegmentNode* cur_sseg = nullptr;
    uint32_t count = 0;
};

#endif

