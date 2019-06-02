function showPasswords(checkbox) {
    let password = document.getElementById("login-password");
    let key_password = document.getElementById("login-second-key");
    if (checkbox.checked) {
        password.type = 'text';
        key_password.type = 'text';
    } else {
        password.type = 'password';
        key_password.type = 'password';
    }
}

function changeLoginOption(selection) {
    if (selection.value === "Encryption Key") {
        document.getElementById("second-key-help").innerText = "This is what you used to encrypt your data.";
    } else if (selection.value === "Private Key") {
        document.getElementById("second-key-help").innerText = "Your private key in hex string form.";
    } else { //Api key - Make input box disappear
        document.getElementById("second-key-help").innerText = "Use Api key for quick login.";
    }

    if (selection.value === "Api Key") {
        document.getElementById("login-second-key").style.display = "none";
    } else {
        document.getElementById("login-second-key").style.display = "block";
    }
}