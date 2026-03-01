#!/bin/bash

# ATTENTION: Make sure apache with ssl is running on localhost:443
# Requires c-icap installed and configured to listen on 1344 with echo service (see c-icap.conf)

# Kill previous instances
pkill lp
pkill sslproxy
pkill c-icap
sleep 2

rm lp.log
rm c-icap.log
rm sslproxy.log
rm curl.log
rm server.log
rm access.log

# Start LP as H1 sink on 9080
./tests/testproxy/lp/lp -D4 127.0.0.1 9080 > lp.log 2>&1 &
LP_PID=$!
echo "Started LP with PID $LP_PID"

# Start c-icap on 10443 as ICAP server
c-icap -N -d 7 -D -f ./c-icap.conf > c-icap.log 2>&1 &
ICAP_PID=$!
echo "Started c-icap with PID $ICAP_PID"

# Start SSLproxy
# Listen on 8080, divert to 9080, backend SSL to 443
./src/sslproxy -D4 -c ./tests/testproxy/ca.crt -k ./tests/testproxy/ca.key -oVerifyPeer=no -X icap.pcap -oIcap="icap://127.0.0.1:1344/echo,serial,bypass" https 127.0.0.1 8080 up:9080 127.0.0.1 443 > sslproxy.log 2>&1 &
PROXY_PID=$!
echo "Started SSLproxy with PID $PROXY_PID"

sleep 2

echo "Sending Request..."
curl --max-time 5 -v -k https://127.0.0.1:8080/ > curl.log 2>&1 &

sleep 2

echo "Cleaning up..."
kill $LP_PID
kill $PROXY_PID
kill $ICAP_PID

sleep 2

echo "-------------------"
echo "LP Log:"
echo "lp logs are not expected to show any errors, just successful connections and requests/responses (traffic goes through lp too)"
cat lp.log
echo "-------------------"
echo "IMPORTANT: sslproxy logs should show successful connections to the backend and ICAP server, no errors"
echo "SSLproxy Log:"
cat sslproxy.log
echo "-------------------"
echo "IMPORTANT: curl should contain the html code for the default apache page on ubuntu"
echo "Curl log:"
cat curl.log
echo "-------------------"
echo "IMPORTANT: c-icap logs must show successful requests and responses, no errors"
echo "c-icap server.log:"
cat server.log
echo "-------------------"
echo "c-icap access.log:"
cat access.log
