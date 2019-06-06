$(document).ready(() => {
    startReportTimer();
    // subscribeToPublicBroadcast();
});

function startReportTimer() {
    //This function will be called on page load, It will periodically report the user to my server by calling the
    // report api. This will be every 35 seconds
    setInterval(()=> {
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

function pollNewMessages() {
    setInterval(()=> {
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

           fetch('/updates/update_online_users', options).then(response => {
            if (response.redirected) {
                location.replace(response.url);
            }
        }).catch(() => {
            console.log("could not report to server")
           });


    }, 35000)
}