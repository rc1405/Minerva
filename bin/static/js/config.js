/*
    Copyright (C) 2015  Ryan M Cote.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

    Author: Ryan M Cote <minervaconsole@gmail.com>
*/
	function saveChanges() {
	    var form1 = document.createElement("form");
	    form1.setAttribute("method", "post");
	    form1.setAttribute("action", "/config");
	    var db_ipField = document.createElement("input");
	    db_ipField.setAttribute("type", "hidden");
	    db_ipField.setAttribute("name", "db_ip");
	    db_ipField.setAttribute("value", document.getElementById('db_ip').value);
	    form1.appendChild(db_ipField);
	    var db_portField = document.createElement("input");
	    db_portField.setAttribute("type", "hidden");
	    db_portField.setAttribute("name", "db_port");
	    db_portField.setAttribute("value", document.getElementById('db_port').value );
	    form1.appendChild(db_portField);
            var useAuthField = document.createElement("input");
            useAuthField.setAttribute("type", "hidden");
            useAuthField.setAttribute("name", "useAuth");
            useAuthField.setAttribute("value", document.getElementById('db_useAuth').checked );
            form1.appendChild(useAuthField);
            var dbuserField = document.createElement("input");
            dbuserField.setAttribute("type", "hidden");
            dbuserField.setAttribute("name", "db_user");
            dbuserField.setAttribute("value", document.getElementById('db_user').value );
            form1.appendChild(dbuserField);
            var dbpassField = document.createElement("input");
            dbpassField.setAttribute("type", "hidden");
            dbpassField.setAttribute("name", "db_pass");
            dbpassField.setAttribute("value", document.getElementById('db_pass').value );
            form1.appendChild(dbpassField);
	    var csrftokenField = document.createElement("input");
	    csrftokenField.setAttribute("type", "hidden");
	    csrftokenField.setAttribute("name", "csrfmiddlewaretoken");
	    csrftokenField.setAttribute("value", document.getElementById("csrf_token").value);
	    form1.appendChild(csrftokenField);
            var webhostField = document.createElement("input");
            webhostField.setAttribute("type", "hidden");
            webhostField.setAttribute("name", "web_host");
            webhostField.setAttribute("value", document.getElementById('web_host').value);
            form1.appendChild(webhostField);
            var web_ipField = document.createElement("input");
            web_ipField.setAttribute("type", "hidden");
            web_ipField.setAttribute("name", "web_ip");
            web_ipField.setAttribute("value", document.getElementById('web_ip').value );
            form1.appendChild(web_ipField);
            var webportField = document.createElement("input");
            webportField.setAttribute("type", "hidden");
            webportField.setAttribute("name", "web_port");
            webportField.setAttribute("value", document.getElementById('web_port').value );
            form1.appendChild(webportField);
            var webthreadField = document.createElement("input");
            webthreadField.setAttribute("type", "hidden");
            webthreadField.setAttribute("name", "web_threads");
            webthreadField.setAttribute("value", document.getElementById('web_threads').value );
            form1.appendChild(webthreadField);
            var cert_pathField = document.createElement("input");
            cert_pathField.setAttribute("type", "hidden");
            cert_pathField.setAttribute("name", "cert_path");
            cert_pathField.setAttribute("value", document.getElementById('cert_path').value );
            form1.appendChild(cert_pathField);
            var key_pathField = document.createElement("input");
            key_pathField.setAttribute("type", "hidden");
            key_pathField.setAttribute("name", "key_path");
            key_pathField.setAttribute("value", document.getElementById('key_path').value );
            form1.appendChild(key_pathField);
            var sesstimedField = document.createElement("input");
            sesstimedField.setAttribute("type", "hidden");
            sesstimedField.setAttribute("name", "session_timeout");
            sesstimedField.setAttribute("value", document.getElementById('session_timeout').value );
            form1.appendChild(sesstimedField);
            var passtriesField = document.createElement("input");
            passtriesField.setAttribute("type", "hidden");
            passtriesField.setAttribute("name", "pass_tries");
            passtriesField.setAttribute("value", document.getElementById('pass_tries').value );
            form1.appendChild(passtriesField);
            var pass_minField = document.createElement("input");
            pass_minField.setAttribute("type", "hidden");
            pass_minField.setAttribute("name", "pass_min");
            pass_minField.setAttribute("value", document.getElementById('pass_min').value );
            form1.appendChild(pass_minField);
            var pass_agedField = document.createElement("input");
            pass_agedField.setAttribute("type", "hidden");
            pass_agedField.setAttribute("name", "pass_age");
            pass_agedField.setAttribute("value", document.getElementById('pass_age').value );
            form1.appendChild(pass_agedField);
            var maxeventsField = document.createElement("input");
            maxeventsField.setAttribute("type", "hidden");
            maxeventsField.setAttribute("name", "max_events");
            maxeventsField.setAttribute("value", document.getElementById('max_events').value );
            form1.appendChild(maxeventsField);
            var max_ageField = document.createElement("input");
            max_ageField.setAttribute("type", "hidden");
            max_ageField.setAttribute("name", "max_age");
            max_ageField.setAttribute("value", document.getElementById('max_age').value );
            form1.appendChild(max_ageField);
            var flow_agedField = document.createElement("input");
            flow_agedField.setAttribute("type", "hidden");
            flow_agedField.setAttribute("name", "flow_age");
            flow_agedField.setAttribute("value", document.getElementById('flow_age').value );
            form1.appendChild(flow_agedField);
            document.body.appendChild(form1);
	    form1.submit();
	}
