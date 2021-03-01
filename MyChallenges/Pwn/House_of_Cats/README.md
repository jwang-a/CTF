# House of Cats hints

## a priori : mp

```
static struct malloc_par mp_ =
{
    .top_pad = DEFAULT_TOP_PAD,
    .n_mmaps_max = DEFAULT_MMAP_MAX,
    .mmap_threshold = DEFAULT_MMAP_THRESHOLD,
    .trim_threshold = DEFAULT_TRIM_THRESHOLD,
#define NARENAS_FROM_NCORES(n) ((n) * (sizeof (long) == 4 ? 2 : 8))
    .arena_test = NARENAS_FROM_NCORES (1)
#if USE_TCACHE
    ,
    .tcache_count = TCACHE_FILL_COUNT,
    .tcache_bins = TCACHE_MAX_BINS,
    .tcache_max_bytes = tidx2usize (TCACHE_MAX_BINS-1),
    .tcache_unsorted_limit = 0 /* No limit.  */
#endif
};
```

### tcache structure extending

glibc2.29

```
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
    tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
    assert (tc_idx < TCACHE_MAX_BINS);

    /* Mark this chunk as "in the tcache" so the test in _int_free will
       detect a double free.  */
    e->key = tcache;

    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    ++(tcache->counts[tc_idx]);
}
```

glibc2.30~

```
static __always_inline void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
    tcache_entry *e = (tcache_entry *) chunk2mem (chunk);

    /* Mark this chunk as "in the tcache" so the test in _int_free will
       detect a double free.  */
    e->key = tcache;

    e->next = tcache->entries[tc_idx];
    tcache->entries[tc_idx] = e;
    ++(tcache->counts[tc_idx]);
}
```

### tcache reanimation

```
while (tcache->counts[tc_idx] < mp_.tcache_count
       && (tc_victim = last (bin)) != bin)
  {
    if (tc_victim != 0)
      {
        bck = tc_victim->bk;
        set_inuse_bit_at_offset (tc_victim, nb);
        if (av != &main_arena)
            set_non_main_arena (tc_victim);
        bin->bk = bck;
        bck->fd = bin;
        tcache_put (tc_victim, tc_idx);
      }
  }
```
