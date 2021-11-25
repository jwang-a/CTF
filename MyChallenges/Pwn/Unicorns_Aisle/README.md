# Unicorn's Aisle

Unicorn Fullchain

Guest Program -unicorn features-> Guest ACE -unicorn 0day-> Host ACE

Solves
          | Solves |
----------|:------:|
prelude   | 12/284 |
interlude | 1/284  |
postlude  | 0/284  |

0day is assigned CVE-2021-44078

## Inspiration

I stumbled upon the 0day while reviewing the code of unicorn engine, and was immediately inspired to create a challenge since
1. The vulnerability seemed trivial enough to discover
2. This bug seems not so dangerous (nobody uses unicorn in production, or do they...)
3. Opposed to common kernel/vm challenges which provide vulnerable drivers, this bug exists in the memory management of unicorn, thus more fun to pwn imo

To set it up and allow people to make progress even if failing to discover the 0day, I further chained it with several other "features" in unicorn engine, and finally came up with the 3-stage challenge

Detailed explaination of each stage + intended solution can be found in the writeup slides.

Enjoy : )

## Writeup

* [Unicorn's Aisle writeup](UnicornsAisle.pdf)
