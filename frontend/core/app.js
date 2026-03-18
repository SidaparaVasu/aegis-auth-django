/**
 * Main Application Logic v2
 * Modular state management using Alpine.js and shared services.
 */

document.addEventListener('alpine:init', () => {
    
    // 1. Global Auth Store
    Alpine.store('auth', {
        isLoggedIn: false,
        user: null,
        token: localStorage.getItem('access_token'),
        timeLeft: 0,
        autoRefresh: localStorage.getItem('auto_refresh') === 'true',
        timerId: null,

        init() {
            if (this.token) {
                this.isLoggedIn = true;
                this.fetchProfile();
                this.startTimer();
            }
        },

        async fetchProfile() {
            const res = await window.API.get('/auth/profile/');
            if (res.ok) {
                this.user = res.data.data;
            } else if (res.status === 401) {
                this.logout();
            }
        },

        saveSession(data) {
            this.token = data.access;
            this.user = data.user;
            this.isLoggedIn = true;
            localStorage.setItem('access_token', data.access);
            localStorage.setItem('refresh_token', data.refresh);
            this.startTimer();
        },

        toggleAutoRefresh() {
            this.autoRefresh = !this.autoRefresh;
            localStorage.setItem('auto_refresh', this.autoRefresh);
        },

        startTimer() {
            if (this.timerId) clearInterval(this.timerId);
            
            const updateTime = () => {
                if (!this.token) return;
                try {
                    const parts = this.token.split('.');
                    if (parts.length < 2) return;
                    
                    const payload = JSON.parse(atob(parts[1]));
                    if (!payload.exp) return;

                    const expiry = payload.exp * 1000;
                    const now = Date.now();
                    this.timeLeft = Math.max(0, Math.floor((expiry - now) / 1000));

                    // Auto-refresh logic (triggered when < 60 seconds left)
                    if (this.autoRefresh && this.timeLeft <= 60 && this.timeLeft > 0) {
                        this.refreshToken();
                    }

                    if (this.timeLeft === 0 && !this.autoRefresh) {
                        this.logout();
                        alert('Session expired. Please log in again.');
                    }
                } catch (e) {
                    console.error('Timer Error:', e);
                }
            };

            updateTime();
            this.timerId = setInterval(updateTime, 1000);
        },

        async refreshToken() {
            const refresh = localStorage.getItem('refresh_token');
            if (!refresh) return;

            // Avoid double calls
            if (this._isRefreshing) return;
            this._isRefreshing = true;

            const res = await window.API.post('/auth/token/refresh/', { refresh });
            this._isRefreshing = false;

            if (res.ok) {
                this.token = res.data.access;
                localStorage.setItem('access_token', this.token);
                if (res.data.refresh) localStorage.setItem('refresh_token', res.data.refresh);
                // Timer will pick up new token automatically in next interval
            } else {
                this.logout();
            }
        },

        formatTime(seconds) {
            const secs = seconds || 0;
            const m = Math.floor(secs / 60);
            const s = Math.floor(secs % 60);
            return `${m}:${s.toString().padStart(2, '0')}`;
        },

        logout() {
            if (this.timerId) clearInterval(this.timerId);
            this.isLoggedIn = false;
            this.user = null;
            this.token = null;
            this.timeLeft = 0;
            localStorage.removeItem('access_token');
            localStorage.removeItem('refresh_token');
            window.location.hash = '#gateway';
        }
    });

    // 2. Main App Controller
    Alpine.data('ctrl', () => ({
        view: 'gateway',
        subView: 'login',
        logs: [],
        
        // Form States
        reg: { email: '', username: '', password: '' },
        login: { email: '', password: '' },
        otp: { purpose: 'LOGIN', code: '' },
        pwd: { old: '', new: '', confirm: '' },
        forgot: { email: '', step: 1, token: '', new_password: '' },
        
        // Data States
        sessions: [],
        configs: [],
        auditLogs: [],
        
        init() {
            // Hash Routing
            const handleRoute = () => {
                const hash = window.location.hash.replace('#', '') || 'gateway';
                this.view = hash;
                this.onViewChange(hash);
            };
            window.addEventListener('hashchange', handleRoute);
            handleRoute();

            // Live Console Observer (Zero-Lag)
            window.API.addEventListener('response', (e) => {
                this.logs.unshift({
                    id: Date.now(),
                    ...e.detail,
                    time: new Date().toLocaleTimeString()
                });
                if (this.logs.length > 30) this.logs.pop();
            });

            // Handle Unauthorized
            window.API.addEventListener('unauthorized', () => {
                Alpine.store('auth').logout();
            });
        },

        onViewChange(view) {
            if (!Alpine.store('auth').isLoggedIn && view !== 'gateway') {
                window.location.hash = '#gateway';
                return;
            }
            
            // Auto-fetch data based on view
            if (view === 'sessions') this.fetchSessions();
            if (view === 'configs') this.fetchConfigs();
            if (view === 'audit') this.fetchAuditLogs();
        },

        // --- AUTH ACTIONS ---
        async handleLogin() {
            const res = await window.API.post('/auth/login/', this.login);
            if (res.ok) {
                Alpine.store('auth').saveSession(res.data.data);
                window.location.hash = '#security';
            }
        },

        async handleRegister() {
            const res = await window.API.post('/auth/register/', this.reg);
            if (res.ok) {
                this.subView = 'login';
                this.login.email = this.reg.email;
                alert('Success! Please log in.');
            }
        },

        async handleForgotRequest() {
            const res = await window.API.post('/auth/password/reset/', {
                email: this.forgot.email
            });
            if (res.ok) {
                this.forgot.step = 2;
                alert('Recovery OTP sent! Check console.');
            }
        },

        async handleForgotConfirm() {
            const res = await window.API.post('/auth/password/reset/confirm/', {
                email: this.forgot.email,
                otp_code: this.forgot.token,
                new_password: this.forgot.new_password
            });
            if (res.ok) {
                alert('Password reset successful! You can now log in.');
                this.subView = 'login';
                this.forgot = { email: '', step: 1, token: '', new_password: '' };
            }
        },

        // --- SECURITY ACTIONS ---
        async fetchSessions() {
            const res = await window.API.get('/auth/sessions/');
            if (res.ok) this.sessions = res.data.data.results || res.data.data;
        },

        async terminateSession(id) {
            const res = await window.API.delete(`/auth/sessions/${id}/`);
            if (res.ok) this.fetchSessions();
        },

        async handleSendOTP() {
            const res = await window.API.post('/auth/otp/send/', {
                email: Alpine.store('auth').user.email,
                purpose: this.otp.purpose
            });
            if (res.ok) alert('OTP Dispatched!');
        },

        async handleVerifyOTP() {
            const res = await window.API.post('/auth/otp/verify/', {
                otp_code: this.otp.code,
                purpose: this.otp.purpose,
                email: Alpine.store('auth').user.email,
            });
            if (res.ok) {
                alert('Identity Verified: Code Valid.');
                this.otp.code = '';
            }
        },

        async handleChangePassword() {
            if (this.pwd.new !== this.pwd.confirm) return alert('Passwords mismatch');
            const res = await window.API.post('/auth/password/change/', {
                old_password: this.pwd.old,
                new_password: this.pwd.new
            });
            if (res.ok) {
                alert('Cipher Updated Successfully.');
                this.pwd = { old: '', new: '', confirm: '' };
            }
        },

        // --- ADMIN ACTIONS ---
        async fetchConfigs() {
            const res = await window.API.get('/system/configs/');
            if (res.ok) this.configs = res.data.data.results || res.data.data;
        },

        async handleUpdateConfig(config) {
            const res = await window.API.patch(`/system/configs/${config.config_key}/`, {
                config_value: config.config_value
            });
            if (res.ok) alert('System parameter updated.');
        },

        async fetchAuditLogs() {
            const res = await window.API.get('/system/event-logs/');
            if (res.ok) this.auditLogs = res.data.data.results || res.data.data;
        }
    }));
});
