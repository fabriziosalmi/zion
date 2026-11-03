# The lab image of one Next.js version. The base is pinned by digest; next, react and react-dom
# are exact. Transitive packages are not locked: the version of next that really ran is
# measured and written into the result, not assumed from this file.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293
ARG NEXT_VERSION
ENV NEXT_TELEMETRY_DISABLED=1 NODE_ENV=production NODE_OPTIONS=--max-old-space-size=768
WORKDIR /app
COPY package.json ./
RUN test -n "$NEXT_VERSION" \
 && npm install --no-audit --no-fund --save-exact "next@${NEXT_VERSION}" react@18.3.1 react-dom@18.3.1
COPY middleware.js ./
COPY pages ./pages
RUN npm run build
USER node
CMD ["npm", "start"]
