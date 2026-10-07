#!/bin/bash
echo 'Checking DNS for wcy2011.top...'
until dig +short wcy2011.top A | grep -q '47.252.4.163'; do
    echo 'DNS not ready yet, waiting 30s...'
    sleep 30
done
echo 'DNS resolved! Applying SSL certificate...'
certbot --nginx -d wcy2011.top -d www.wcy2011.top --non-interactive --agree-tos --email admin@wcy2011.top --redirect
echo 'Done! HTTPS is now active at https://wcy2011.top'
