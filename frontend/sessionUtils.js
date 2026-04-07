// Call after any API fetch. Returns true if the session expired (caller should stop processing).
function checkAuth(response) {
    if (response.status === 401) {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        localStorage.removeItem('email');
        localStorage.removeItem('userEmail');
        alert('Your session has expired. Please log in again.');
        window.location.href = 'login.html';
        return true;
    }
    return false;
}
