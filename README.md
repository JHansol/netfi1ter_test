# netfi1ter_test

*netfilter_queue* Example. Block Harmful site.

# environment setting

``` apt install libnetfilter-queue-dev ```

# iptables setting

``` iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 0 ```
