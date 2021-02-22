On his name
===========

Using dnstap for triggering action from DNS name resolution.

It should work with any DNS server with dnstap output, tested with Coredns.

Test it
-------

Launch `coredns` in the folder with the `Corefile`.

Launch the service :

    LISTEN=./tap.sock ./bin/on-his-name *.example.com

You can digg :

    dig @localhost -p 1053 blog.example.com
