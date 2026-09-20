const loginTab =
    document.getElementById("loginTab");

const signupTab =
    document.getElementById("signupTab");

const loginPanel =
    document.getElementById("loginPanel");

const signupPanel =
    document.getElementById("signupPanel");

const loginForm =
    document.getElementById("loginForm");

const signupForm =
    document.getElementById("signupForm");

const loginMessage =
    document.getElementById("loginMessage");

const signupMessage =
    document.getElementById("signupMessage");

const loginButton =
    document.getElementById("loginButton");

const signupButton =
    document.getElementById("signupButton");

const loginEmail =
    document.getElementById("loginEmail");

const loginPassword =
    document.getElementById("loginPassword");

const signupName =
    document.getElementById("signupName");

const signupSurname =
    document.getElementById("signupSurname");

const signupEmail =
    document.getElementById("signupEmail");

const signupPassword =
    document.getElementById("signupPassword");

const signupConfirmPassword =
    document.getElementById("signupConfirmPassword");


// ============================================================
// AUTHENTICATION MODE
// ============================================================

function setAuthenticationMode(mode) {

    const isLogin =
        mode === "login";

    loginTab.classList.toggle(
        "active",
        isLogin
    );

    signupTab.classList.toggle(
        "active",
        !isLogin
    );

    loginPanel.style.display =
        isLogin
            ? "block"
            : "none";

    signupPanel.style.display =
        isLogin
            ? "none"
            : "block";

    clearMessage(loginMessage);
    clearMessage(signupMessage);
}


// ============================================================
// MESSAGE
// ============================================================

function showMessage(
    element,
    message,
    type = ""
) {

    if (!element) {
        return;
    }

    element.textContent =
        message;

    element.className =
        "authentication-message";

    if (type) {
        element.classList.add(type);
    }
}


function clearMessage(element) {

    if (!element) {
        return;
    }

    element.textContent =
        "";

    element.className =
        "authentication-message";
}


// ============================================================
// TAB EVENTS
// ============================================================

loginTab.addEventListener(
    "click",
    () => {
        setAuthenticationMode("login");
    }
);


signupTab.addEventListener(
    "click",
    () => {
        setAuthenticationMode("signup");
    }
);


// ============================================================
// LOGIN
// ============================================================

loginForm.addEventListener(
    "submit",
    event => {

        event.preventDefault();

        clearMessage(loginMessage);

        const email =
            loginEmail.value.trim();

        const password =
            loginPassword.value;

        if (!email || !password) {

            showMessage(
                loginMessage,
                "Please enter your email and password.",
                "error"
            );

            return;
        }

        showMessage(
            loginMessage,
            "Login backend is not connected yet.",
            "pending"
        );
    }
);


// ============================================================
// SIGN UP
// ============================================================

signupForm.addEventListener(
    "submit",
    event => {

        event.preventDefault();

        clearMessage(signupMessage);

        const name =
            signupName.value.trim();

        const surname =
            signupSurname.value.trim();

        const email =
            signupEmail.value.trim();

        const password =
            signupPassword.value;

        const confirmPassword =
            signupConfirmPassword.value;


        if (
            !name ||
            !surname ||
            !email ||
            !password ||
            !confirmPassword
        ) {

            showMessage(
                signupMessage,
                "Please complete all fields.",
                "error"
            );

            return;
        }


        if (
            password !==
            confirmPassword
        ) {

            showMessage(
                signupMessage,
                "Passwords do not match.",
                "error"
            );

            return;
        }


        showMessage(
            signupMessage,
            "Registration backend is not connected yet.",
            "pending"
        );
    }
);


// ============================================================
// INITIAL STATE
// ============================================================

setAuthenticationMode("login");