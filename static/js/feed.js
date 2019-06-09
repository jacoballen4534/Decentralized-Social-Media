$(document).ready(() => {
    //This function starts all of the set timeouts on page load
    startReportTimer();
    pollListUsers();
    pollNewMessages();
    callPingCheck();
    converter = new showdown.Converter();
});

//These are here to allow stopInterval
let reportInterval;
let listUsersInterval;
let updateMessagesInterval;
let converter;
let pingCheckinterval;


function startReportTimer() {
    //This function will be called on page load, It will periodically report the user to my server by calling the
    // report api. This will be every 35 seconds
    let missed_reports = 0;
    reportInterval = setInterval(() => {
        //Define a generic payload to send to the server.
        const payload = {
            'request': 'report',
        };

        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(payload)
        };

        fetch('/api/report', options).then(response => {
            if (response.redirected) {
                location.replace(response.url);
            }
            missed_reports = 0;
        }).catch(() => {
            console.log("could not report to server");
            missed_reports++;
            if (missed_reports > 4) { //If the client hasn't been able to reach the server for 2 minutes, log off.
                location.replace("/");
            }
        });

    }, 35000)
}

function pollListUsers() {
    //Update the list of online users every 8 seconds
    listUsersInterval = setInterval(() => {
        //Define a generic payload to send to the server.
        const payload = {
            'request': 'update_user_list',
        };

        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(payload)
        };

        fetch('/updates/update_online_users', options).then(response => {
            return response.json();
        }).then((html_list) => {
            let list = document.getElementById('user_list');
            list.innerHTML = html_list;
            console.log("Updated user list")
        }).catch()
    }, 8000)
}

function pollNewMessages() {
    //Ask my server for any new messages every 3 seconds
    updateMessagesInterval = setInterval(() => {
            //Tell the server the id of the last message it received.
            let broadcast_list = document.getElementById("broadcasts");
            let lastMessageId = 0;
            if (broadcast_list.children.length > 0) {
                lastMessageId = broadcast_list.children[0].getAttribute('data-message-id');
            }
            let payload = {
                'request': 'update_user_list',
                'last_message': lastMessageId,
            };

            const options = {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json; charset=utf-8',
                },
                body: JSON.stringify(payload)
            };

            fetch('/updates/update_new_broadcasts', options).then(response => {
                return response.json();
            }).then((html_messages) => {
                let list = document.getElementById('broadcasts');

                if (html_messages.length <= 0) {
                    return;
                }

                let lastMessageAdded = list.children[0].getAttribute("data-message-id");
                let newMessages = html_messages.split('<div class="card mr-4 mb-4" id=');

                for (let i = 1; i < newMessages.length; i++) {
                    let newMessageNumber = newMessages[i].split("message-number-")[1].split('"')[0];
                    if (newMessageNumber > lastMessageAdded) {
                        lastMessageAdded = newMessageNumber;
                        list.innerHTML = '<div class="card mr-4 mb-4" id="' + newMessages[i] + list.innerHTML;
                    }
                }
            }).catch()
        },3000
    )
}

function searchMessage() {

    let broadcast_list = document.getElementById("broadcasts");
    let searchBoxContents = document.getElementById("search-message-box").value;
    if (searchBoxContents.length <= 0) {
        return
    }
    console.log("search pressed");
    clearInterval(updateMessagesInterval);
    let payload = {
        'request': 'search_broadcasts',
        'message_from': searchBoxContents,
    };

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify(payload)
    };

    fetch('/updates/search_broadcasts', options).then(response => {
        return response.json();
    }).then((md_messages) => {
        let list = document.getElementById('broadcasts');
        list.innerHTML = md_messages;
        console.log("Searched New messages")
    }).catch()
}


function sendBroadcast() {

    let message = document.getElementById("broadcast-message-box").value;
    if (message.length <= 0) {
        return
    }
    console.log("Send message clicked");
    //Clear the message box and the markdown preview
    document.getElementById("broadcast-message-box").value = "";
    document.getElementById("outer-message-container").children[0].value = "";
    document.getElementById("outer-message-container").children[1].innerHTML = "";
    document.getElementById("markdown-preview").innerHTML = "";
    let payload = {
        'request': 'send_message',
        'message': message,
    };

    const options = {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json; charset=utf-8',
        },
        body: JSON.stringify(payload)
    };
    // Dont need the result
    fetch('/updates/send_broadcast', options).catch()
}


function previewMarkdownMessage() {
    // for (let i = 0; i < )
    let message = document.getElementById("broadcast-message-box").value;
    let trimmedMd = message.trim(); //Remove leading and trailing white space
    let previewBox = document.getElementById("markdown-preview");
    let previewMessage = converter.makeHtml(trimmedMd);
    previewBox.innerHTML = previewMessage;
}

function convertAllMessagesToMd(button) {
    let messageId = button.getAttribute('data-parent-id');
    let parrentCard = document.getElementById("message-number-" + messageId);
    let md = parrentCard.children[0].children[1].innerHTML;

    let trimmedMd = md.trim(); //Remove leading and trailing white space

    let htmlMessage = converter.makeHtml(trimmedMd);
    parrentCard.children[0].children[1].innerHTML = htmlMessage;
}


function callPingCheck() {
    //Ping check all other servers every minute
    pingCheckinterval = setInterval(() => {
        //Tell the server the id of the last message it received.

        let payload = {
            'request': 'call_ping_check',
        };

        const options = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json; charset=utf-8',
            },
            body: JSON.stringify(payload)
        };

        fetch('/updates/call_ping_check', options).catch()
    }, 60000)
}