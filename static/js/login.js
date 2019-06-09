function showPasswords(checkbox) {
    let password = document.getElementById("login-password");
    let key_password = document.getElementById("login-key");
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
        document.getElementById("login-key-help").innerText = "This is what you used to encrypt your data.";
    } else if (selection.value === "Private Key") {
        document.getElementById("login-key-help").innerText = "Your private key in hex string form.";
    } else { //Api key - Make input box disappear
        document.getElementById("login-key-help").innerText = "Use Api key for quick login.";
    }

    if (selection.value === "Api Key") {
        document.getElementById("login-key").style.display = "none";
    } else {
        document.getElementById("login-key").style.display = "block";
    }
}


(() => {
        'use strict';
        window.addEventListener('load', () => {
            // Fetch all the forms we want to apply custom Bootstrap validation styles to
            let forms = document.getElementsByClassName('needs-validation');
            //remove un needed elements

            // Loop over them and prevent submission
            Array.prototype.filter.call(forms, form => {
                form.addEventListener('submit', event => {
                    if (form.checkValidity() === false) {
                        event.preventDefault();
                        event.stopPropagation();
                    } else {
                        //If they all passed, disable the button.
                        let button = document.getElementById("login-button");
                        button.disabled = true;
                        button.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Verifying...';
                    }
                    form.classList.add('was-validated');
                }, false)
            });
        }, false);
    }
)();