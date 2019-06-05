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
        try {
           fetch('/api/report', options).then(response => {
            if (response.redirected) {
                location.replace(response.url);
            }
        })
        } catch (e) {
            ;
        }

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

    source.addEventListener("data", function (event) {
        console.log("From data listener:\n" + event.data)
    });

    source.onmessage = (event) => {
        console.log("From data message:\n" + event.id, event.data);

        if (event.id === "CLOSE") {
            source.close()
        }
    }
}