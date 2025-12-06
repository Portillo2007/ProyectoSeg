// Detectar automáticamente la URL actual
const API_URL = window.location.origin;

// Verificar si la sesión es válida y única
async function checkSession() {
    const token = localStorage.getItem("token");
    const sessionKey = sessionStorage.getItem("sessionKey");
    
    if (!token || !sessionKey) {
        localStorage.removeItem("token");
        localStorage.removeItem("userId");
        sessionStorage.removeItem("sessionKey");
        return false;
    }
    
    try {
        const response = await fetch(API_URL + "/my-texts", {
            method: "GET",
            headers: { "Authorization": token }
        });
        
        // Si el token es inválido, limpiar todo
        if (response.status === 401 || response.status === 403) {
            localStorage.removeItem("token");
            localStorage.removeItem("userId");
            sessionStorage.removeItem("sessionKey");
            return false;
        }
        
        return response.ok;
    } catch (error) {
        return false;
    }
}

// Generar clave de sesión única
function generateSessionKey() {
    return Math.random().toString(36).substring(2, 15) + 
           Date.now().toString(36);
}

// ----- REGISTRO -----
async function registerUser(username, password) {
    const response = await fetch(API_URL + "/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();
    alert(data.msg);

    if (data.ok) window.location.href = "index.html";
}

// ----- LOGIN -----
async function loginUser(username, password) {
    const response = await fetch(API_URL + "/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (data.ok) {
        localStorage.setItem("token", data.token);
        localStorage.setItem("userId", data.userId);
        // Generar y guardar clave de sesión única
        sessionStorage.setItem("sessionKey", generateSessionKey());
        return true;
    }

    alert(data.msg);
    return false;
}

// ----- GUARDAR CIFRADO -----
async function saveCipher(cipher) {
    const response = await fetch(API_URL + "/save-text", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Authorization": localStorage.getItem("token")
        },
        body: JSON.stringify({ cipher })
    });

    return await response.json();
}

// ----- CERRAR SESIÓN -----
function logout() {
    localStorage.removeItem("token");
    localStorage.removeItem("userId");
    sessionStorage.removeItem("sessionKey");
    window.location.href = "index.html";
}

// ----- OBTENER HISTORIAL -----
async function getMyTexts() {
    const response = await fetch(API_URL + "/my-texts", {
        method: "GET",
        headers: {
            "Authorization": localStorage.getItem("token")
        }
    });

    return await response.json();
}
