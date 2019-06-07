$(document).ready(() => {
    //This function starts all of the set timeouts on page load
    startReportTimer();
    pollListUsers();
    pollNewMessages();
});

//These are here to allow stopInterval
let reportInterval;
let listUsersInterval;
let updateMessagesInterval;


function startReportTimer() {
    //This function will be called on page load, It will periodically report the user to my server by calling the
    // report api. This will be every 35 seconds
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
        }).catch(() => {
            console.log("could not report to server")
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
        })
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
            list.innerHTML = html_messages + list.innerHTML;
            console.log("Updated New messages")
        })
    }, 3000)
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
    }).then((html_messages) => {
        let list = document.getElementById('broadcasts');
        list.innerHTML = html_messages;
        console.log("Searched New messages")
    })
}

function sendBroadcast() {

    let message = document.getElementById("broadcast-message-box").value;
    if (message.length <= 0) {
        return
    }
    console.log("Send message clicked");
    document.getElementById("broadcast-message-box").value = "";

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
    fetch('/updates/send_broadcast', options)
}