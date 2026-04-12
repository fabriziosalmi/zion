import http from 'k6/http';
import { check } from 'k6';

// Parameters injected via environment
const BASE_URL = __ENV.TARGET_URL || 'https://127.0.0.1:8443';
const ENDPOINT = __ENV.ENDPOINT || '/api/v1/data';
const METHOD = (__ENV.METHOD || 'GET').toUpperCase();
const VUS = parseInt(__ENV.VUS || '100');
const DURATION = __ENV.DURATION || '15s';

export const options = {
    vus: VUS,
    duration: DURATION,
    insecureSkipTLSVerify: true,
    noConnectionReuse: false,
};

const headers = { 'Host': 'bench.local' };
const postBody = JSON.stringify({
    username: 'testuser',
    email: 'test@example.com',
    data: { nested: true },
});

export default function () {
    let res;
    if (METHOD === 'POST') {
        res = http.post(`${BASE_URL}${ENDPOINT}`, postBody, {
            headers: { ...headers, 'Content-Type': 'application/json' },
        });
    } else {
        res = http.get(`${BASE_URL}${ENDPOINT}`, { headers });
    }
    check(res, { 'status 200': (r) => r.status === 200 });
}
