const express = require('express')
const path = require('path')
const app = express()
const snmp = require("net-snmp");
//Express Setter
require('events').EventEmitter.defaultMaxListeners = Infinity
app.set('view engine', 'pug');
app.set('views', path.join(__dirname, 'views'));


app.get('/:ip', async (req, res) => {

    //Get SNMP on Range of IP Address
    var session = snmp.createSession(req.params.ip, "public");
    var result = []
    var oids = [
        "1.3.6.1.2.1.1.1.0", //sysDescr
        "1.3.6.1.2.1.1.2.0", //sysObjectID
        "1.3.6.1.2.1.1.3.0", //sysUpTime
        "1.3.6.1.2.1.1.4.0", //sysContact
        "1.3.6.1.2.1.1.5.0", //sysName
        "1.3.6.1.2.1.1.6.0", //sysLocation
        "1.3.6.1.2.1.1.7.0", //sysServices

        //System Resource Section
        "1.3.6.1.2.1.25.2.3.1.6.65536", //used-memory
        "1.3.6.1.2.1.25.2.3.1.5.65536", //total-memory
        "1.3.6.1.4.1.14988.1.1.3.14.0", //cpu-frequency

        //Wireless Registration Table
        "1.3.6.1.4.1.14988.1.1.1.2.1.3.116.77.40.131.183.17.1",  //signal-strength
        "1.3.6.1.4.1.14988.1.1.1.2.1.19.116.77.40.131.183.17.1", //tx-signal-strength
        "1.3.6.1.4.1.14988.1.1.1.2.1.10.116.77.40.131.183.17.1", //routeros-version
        "1.3.6.1.4.1.14988.1.1.1.2.1.11.116.77.40.131.183.17.1", //uptime
        "1.3.6.1.4.1.14988.1.1.1.2.1.12.116.77.40.131.183.17.1", //signal-to-noise
        "1.3.6.1.4.1.14988.1.1.1.2.1.13.116.77.40.131.183.17.1", //tx-signal-strength-ch0
        "1.3.6.1.4.1.14988.1.1.1.2.1.14.116.77.40.131.183.17.1", //signal-strength-ch0
        "1.3.6.1.4.1.14988.1.1.1.2.1.15.116.77.40.131.183.17.1", //tx-signal-strength-ch1
        "1.3.6.1.4.1.14988.1.1.1.2.1.16.116.77.40.131.183.17.1", //signal-strength-ch1
        "1.3.6.1.4.1.14988.1.1.1.2.1.17.116.77.40.131.183.17.1", //tx-signal-strength-ch2
        "1.3.6.1.4.1.14988.1.1.1.2.1.18.116.77.40.131.183.17.1", //signal-strength-ch2
        "1.3.6.1.4.1.14988.1.1.1.2.1.20.116.77.40.131.183.17.1", //radio-name

        //Queue Simple
        "1.3.6.1.4.1.14988.1.1.2.1.1.2.1",   //name
        "1.3.6.1.4.1.14988.1.1.2.1.1.10.1",  //packets-in
        "1.3.6.1.4.1.14988.1.1.2.1.1.11.1",  //packets-out

    ];

    var key = ["sysDescr", "sysObjectID", "sysUpTime", "sysContact", "sysName", "sysLocation", "sysServices",
        "used-memory", "total-memory", "cpu-frequency", "signal-strength", "tx-signal-strength", "routeros-version", "uptime",
        "signal-to-noise", "tx-signal-strength-ch0", "signal-strength-ch0", "tx-signal-strength-ch1", "signal-strength-ch1",
        "tx-signal-strength-ch2", "signal-strength-ch2", "radio-name", "name", "packets-in", "packets-out"];

    session.get(oids, function (error, varbinds) {
        if (error) {
            console.error(error);
        } else {
            for (var i = 0; i < varbinds.length; i++)
                if (snmp.isVarbindError(varbinds[i]))
                    console.error(snmp.varbindError(varbinds[i]))
                else {
                    if (varbinds[i].oid == "1.3.6.1.2.1.1.3.0" || varbinds[i].oid == "1.3.6.1.4.1.14988.1.1.1.2.1.11.116.77.40.131.183.17.1") {
                        var temp = varbinds[i].value;
                        temp = temp * 0.00016666666666667;
                        result[i] = varbinds[i].oid + " = " + time_convert(temp)
                    } else if (varbinds[i].oid == "1.3.6.1.4.1.14988.1.1.2.1.1.10.1" || varbinds[i].oid == "1.3.6.1.4.1.14988.1.1.2.1.1.11.1") {
                        var temp = varbinds[i].value;
                        temp = temp / 1024;
                        result[i] = varbinds[i].oid + " = " + temp
                    } else {
                        result[i] = varbinds[i].oid + " = " + varbinds[i].value
                    }
                }
        }
        session.close();
    });
    session.trap(snmp.TrapType.LinkDown, function (error) {
        if (error)
            console.error(error);
    });

    setTimeout(() => {
        res.render('home', { title: 'SNMP Checker', list: result, data: key })
    }, 50);

    function time_convert(num) {
        var days = Math.floor(num / 1440);
        var hours = Math.floor((num / 60) % 24);
        var minutes = Math.floor(num % 60);
        return days + " days :" + hours + " hours :" + minutes + " minutes";
    }
})


app.listen(80)