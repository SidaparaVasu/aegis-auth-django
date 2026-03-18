/**
 * API Bridge v2
 * High-reliability fetch wrapper with automatic token management and event-bus logging.
 */
class ApiBridge extends EventTarget {
    constructor() {
        super();
        this.BASE_URL = '/api/v1';
    }

    async request(method, path, body = null, headers = {}) {
        const url = `${this.BASE_URL}${path}`;
        const access = localStorage.getItem('access_token');

        const config = {
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        };

        if (access) {
            config.headers['Authorization'] = `Bearer ${access}`;
        }

        if (body) {
            config.body = JSON.stringify(body);
        }

        const stats = { startTime: performance.now() };

        try {
            const response = await fetch(url, config);
            stats.endTime = performance.now();
            
            let data = {};
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                data = await response.json();
            }

            const result = {
                ok: response.ok,
                status: response.status,
                data: data,
                meta: {
                    latency: `${Math.round(stats.endTime - stats.startTime)}ms`,
                    method,
                    path
                }
            };

            // Dispatch event for Live Console
            this.dispatchEvent(new CustomEvent('response', { detail: result }));

            // Handle Unauthorized (Auto Logout flow)
            if (response.status === 401 && access) {
                this.dispatchEvent(new CustomEvent('unauthorized'));
            }

            return result;
        } catch (error) {
            const errResult = {
                ok: false,
                status: 0,
                data: { message: 'Network Failure', errors: { details: error.message } },
                meta: { latency: '0ms', method, path }
            };
            this.dispatchEvent(new CustomEvent('response', { detail: errResult }));
            return errResult;
        }
    }

    get(path) { return this.request('GET', path); }
    post(path, data) { return this.request('POST', path, data); }
    patch(path, data) { return this.request('PATCH', path, data); }
    delete(path) { return this.request('DELETE', path); }
}

const API = new ApiBridge();
window.API = API; 
