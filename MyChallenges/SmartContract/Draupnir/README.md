# Draupnir

ganache-core 2.13.2 forked blockchain evm impl 0day 

desync between storage and eth balance allows double spend and all kinds of mischieve

Solves : 0/284

## Inspiration

Early this year, I spent some day studying how evm works and found this bug.

Similar to Unicorn's Aisle (another series of sanbox/pwn challenge presented in balsnctf this year), the bug is extremely easy to trigger and **should** be discoverable through some fuzzing/trial and error.

Contrarily, root cause of this bug is a bit more complex than in Unicorn's Aisle while exploit is fairly easy

I originally planned to present this challenge is WCTF due to it's difficulty extraordinarily enlightening nature.

However, due to cancellation of WCTF plus our domestic smart contract expert decided not to make any challenges this year, this became a balsnctf challenge in the end.

For detailed analysis of bug, see writeup below.

Hope you guys enjoy the challenge :)

## Writeup

* [Draupnir writeup](Draupnir.pdf)
