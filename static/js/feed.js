$(document).ready(() => {
    startReportTimer();
    subscribeToPublicBroadcast();
});

function startReportTimer() {
    //This function will be called on page load, It will periodically report the user to my server by calling the
    // report api. This will be every 35 seconds
    let missed_reports = 0;
    setInterval(() => {
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


function subscribeToPublicBroadcast() {
    //This function will create a new event source, this will allow the browser to subscribe to the servers
    // update_public_broadcasts endpoint. This will allow the client to instantly get new messages.

    let source = new EventSource('/api/update_public_broadcasts');

    source.onopen = function () {
        console.log("New broadcast update connection established");
    };

    source.onerror = () => {
        console.log("broadcast error function");
    };

    source.addEventListener("new_broadcast", function (event) {
        console.log("Her is a new broadcast:\n" + event.data)
    });

    source.onmessage = (event) => {
        console.log("From data message:\n" + event.id, event.data);

        if (event.id === "CLOSE") {
            source.close()
        }
    }
}