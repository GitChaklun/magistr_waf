FROM openresty/openresty:alpine

# install git and curl to fetch lua-resty-waf (minimal)
RUN apk add --no-cache git bash curl

# Clone lua-resty-waf (simple WAF in Lua) and copy rules (adjust as needed)
RUN mkdir -p /usr/local/openresty/lualib/waf
RUN git clone https://github.com/p0pr0ck5/lua-resty-waf.git /tmp/lua-resty-waf || true
RUN cp -r /tmp/lua-resty-waf/* /usr/local/openresty/lualib/waf/ || true

# Copy nginx.conf from context (override)
COPY nginx.conf /usr/local/openresty/nginx/conf/nginx.conf

# Create results dir
RUN mkdir -p /var/log/waf_results
WORKDIR /usr/local/openresty

EXPOSE 80

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]

