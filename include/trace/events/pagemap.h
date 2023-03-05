/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM pagemap

#if !defined(_TRACE_PAGEMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_PAGEMAP_H

#include <linux/tracepoint.h>
#include <linux/mm.h>

#define	PAGEMAP_MAPPED		0x0001u
#define PAGEMAP_ANONYMOUS	0x0002u
#define PAGEMAP_FILE		0x0004u
#define PAGEMAP_SWAPCACHE	0x0008u
#define PAGEMAP_SWAPBACKED	0x0010u
#define PAGEMAP_MAPPEDDISK	0x0020u
#define PAGEMAP_BUFFERS		0x0040u

#define trace_pagemap_flags(folio) ( \
	(folio_test_anon(folio)		? PAGEMAP_ANONYMOUS  : PAGEMAP_FILE) | \
	(folio_mapped(folio)		? PAGEMAP_MAPPED     : 0) | \
	(folio_test_swapcache(folio)	? PAGEMAP_SWAPCACHE  : 0) | \
	(folio_test_swapbacked(folio)	? PAGEMAP_SWAPBACKED : 0) | \
	(folio_test_mappedtodisk(folio)	? PAGEMAP_MAPPEDDISK : 0) | \
	(folio_test_private(folio)	? PAGEMAP_BUFFERS    : 0) \
	)

TRACE_EVENT(mm_lru_insertion,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long, page_addr)
		__field(unsigned long,	pfn	)
		__field(enum lru_list,	lru	)
		__field(unsigned long,	flags	)
		__field(unsigned int, nr_access)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr = (unsigned long)(unsigned long)(folio);
		__entry->pfn	= folio_pfn(folio);
		__entry->lru	= folio_lru_list(folio);
		__entry->flags	= trace_pagemap_flags(folio);
		__entry->nr_access = folio->page.nr_access;
	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p page=0x%lx pfn=0x%lx lru=%d flags=%s%s%s%s%s%s nr_access=%d",
			__entry->folio,
			__entry->page_addr,
			__entry->pfn,
			__entry->lru,
			__entry->flags & PAGEMAP_MAPPED		? "M" : " ",
			__entry->flags & PAGEMAP_ANONYMOUS	? "a" : "f",
			__entry->flags & PAGEMAP_SWAPCACHE	? "s" : " ",
			__entry->flags & PAGEMAP_SWAPBACKED	? "b" : " ",
			__entry->flags & PAGEMAP_MAPPEDDISK	? "d" : " ",
			__entry->flags & PAGEMAP_BUFFERS	? "B" : " ",
			__entry->nr_access)
	);

TRACE_EVENT(page_access,

	TP_PROTO(struct folio *folio),
	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long, page_addr)
		__field(unsigned long,	pfn	)
		__field(unsigned int, nr_access)
		__field(enum lru_list,	lru	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr = (unsigned long)(folio);
		__entry->pfn	= folio_pfn(folio);
		//__entry->nr_accesses	= 0;
		__entry->nr_access = folio->page.nr_access;
		__entry->lru	= folio_lru_list(folio);

	),

	/* Flag format is based on page-types.c formatting for pagemap */
	TP_printk("folio=%p page=0x%lx pfn=0x%lx nr_access=%d lru=%d",
			__entry->folio,
			__entry->page_addr,
			__entry->pfn,
			__entry->nr_access,
			__entry->lru)
	);

TRACE_EVENT(mm_lru_activate,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	)
		__field(unsigned long, page_addr)
		__field(unsigned long,	pfn	)
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr = (unsigned long)folio_address(folio);
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p page=0x%lx pfn=0x%lx", __entry->folio, __entry->page_addr, __entry->pfn)
);


/* Deactivating folios and setting them up for reclaim */
TRACE_EVENT(mm_lru_deactivate_file,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	 )
		__field(unsigned long, page_addr )
		__field(unsigned long,	pfn	 )
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr 	= (unsigned long)folio_address(folio);
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p page=0x%lx pfn=0x%lx", __entry->folio, __entry->page_addr, __entry->pfn)
);

TRACE_EVENT(mm_lru_deactivate,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	 )
		__field(unsigned long, page_addr )
		__field(unsigned long,	pfn	 )
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr 	= (unsigned long)folio_address(folio);
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p page=0x%lx pfn=0x%lx", __entry->folio, __entry->page_addr, __entry->pfn)
);

/* Lazy free for clean anon folios. This is to differentiate from dirty anon folios */

TRACE_EVENT(mm_lru_lazyfree,

	TP_PROTO(struct folio *folio),

	TP_ARGS(folio),

	TP_STRUCT__entry(
		__field(struct folio *,	folio	 )
		__field(unsigned long, page_addr )
		__field(unsigned long,	pfn	 )
	),

	TP_fast_assign(
		__entry->folio	= folio;
		__entry->page_addr 	= (unsigned long)folio_address(folio);
		__entry->pfn	= folio_pfn(folio);
	),

	TP_printk("folio=%p page=0x%lx pfn=0x%lx", __entry->folio, __entry->page_addr, __entry->pfn)
);


#endif /* _TRACE_PAGEMAP_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
