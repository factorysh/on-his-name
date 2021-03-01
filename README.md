On his name
===========

Using dnstap for triggering action from DNS name resolution.

It should work with any DNS server with dnstap output, tested with Coredns.

Test it
-------

With a `setcap`, *coredns* doesn't have to be run as root,
but `on-his-name` uses `iptables` and needs to be run as root.

Launch `coredns` in the folder with the `Corefile`.

Launch the service :

    LISTEN=./tap.sock SOCKET_UID=1000 ./bin/on-his-name *.example.com

You can dig :

    dig @localhost -p 1053 blog.example.com
