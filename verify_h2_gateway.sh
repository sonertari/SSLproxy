#!/bin/bash

# Kill previous instances
pkill lp
pkill sslproxy
pkill nghttpd
sleep 1

# Start LP as H1 sink on 9080 (the actual target of our translation logic)
./tests/testproxy/lp/lp -D3 127.0.0.1 9080 > lp.log 2>&1 &
LP_PID=$!
echo "Started LP with PID $LP_PID"

# Start nghttpd on 10443 as H2 server (the target of curl requests)
# We use the existing server certificates and set docroot to .
nghttpd -v -d . 10443 tests/testproxy/server.key tests/testproxy/server.crt > nghttpd.log 2>&1 &
NG_PID=$!
echo "Started nghttpd with PID $NG_PID"

# Start SSLproxy
# Listen on 8080, divert H1 to 9080, backend SSL H2 to 10443
./src/sslproxy -D3 -c tests/testproxy/ca.crt -k tests/testproxy/ca.key -oVerifyPeer=no https 127.0.0.1 8080 up:9080 127.0.0.1 10443 > sslproxy.log 2>&1 &
PROXY_PID=$!
echo "Started SSLproxy with PID $PROXY_PID"

sleep 2

echo "Sending Request..."
curl --max-time 5 -v -k --http2 https://127.0.0.1:8080/ > curl.log 2>&1 &

sleep 2

echo "Cleaning up..."
kill $LP_PID
kill $PROXY_PID
kill $NG_PID

echo "LP Log:"
cat lp.log
echo "-------------------"
echo "SSLproxy Log:"
cat sslproxy.log
echo "-------------------"
echo "IMPORTANT: curl and nghttpd logs must show 404 Not Found response code"
echo "Curl log:"
cat curl.log
echo "-------------------"
echo "nghttpd log:"
cat nghttpd.log
