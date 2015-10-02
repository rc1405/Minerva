{#
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
#}
	<script>
	function createUser () {
            var updateType = document.getElementById('updateType').value;
	    var form1 = document.createElement("form");
	    form1.setAttribute("method", "post");
	    form1.setAttribute("action", "/users");
	    var hiddenField = document.createElement("input");
	    hiddenField.setAttribute("type", "hidden");
	    hiddenField.setAttribute("name", "username");
	    hiddenField.setAttribute("value", document.getElementById('username').value);
	    form1.appendChild(hiddenField);
            password = document.getElementById('password').value;
            if (document.getElementById('username').value.length < 4)
            {
                alert('Username not present or too short');
                return;
            }
            else if (updateType == 'new_user' && password.length < 8 ) 
            {
                alert('Password Not Long Enough');
                return;
            } 
            else if (updateType == 'editUser' && password.length > 0 && password.lengh < 8 ) 
            {
                alert('Password Not Long Enough to Change');
                return;
            } 
            else if (updateType == 'editUser' && password.length == 0 )
            {
                updateType = 'updatePerms';
            } 
            else if (updateType == 'editUser' ) 
            {
                updateType = 'updateUser';
            }
	    var hiddenField1 = document.createElement("input");
	    hiddenField1.setAttribute("type", "hidden");
	    hiddenField1.setAttribute("name", "password");
	    hiddenField1.setAttribute("value", password );
	    form1.appendChild(hiddenField1);
            var hiddenField2 = document.createElement("input");
            hiddenField2.setAttribute("type", "hidden");
            hiddenField2.setAttribute("name", "console");
            hiddenField2.setAttribute("value", document.getElementById('console').checked );
            form1.appendChild(hiddenField2);
            var hiddenField3 = document.createElement("input");
            hiddenField3.setAttribute("type", "hidden");
            hiddenField3.setAttribute("name", "responder");
            hiddenField3.setAttribute("value", document.getElementById('responder').checked );
            form1.appendChild(hiddenField3);
            var hiddenField4 = document.createElement("input");
            hiddenField4.setAttribute("type", "hidden");
            hiddenField4.setAttribute("name", "sensor_admin");
            hiddenField4.setAttribute("value", document.getElementById('sensor_admin').checked );
            form1.appendChild(hiddenField4);
            var hiddenField5 = document.createElement("input");
            hiddenField5.setAttribute("type", "hidden");
            hiddenField5.setAttribute("name", "user_admin");
            hiddenField5.setAttribute("value", document.getElementById('user_admin').checked );
            form1.appendChild(hiddenField5);
            var hiddenField6 = document.createElement("input");
            hiddenField6.setAttribute("type", "hidden");
            hiddenField6.setAttribute("name", "server_admin");
            hiddenField6.setAttribute("value", document.getElementById('server_admin').checked );
            form1.appendChild(hiddenField6);
	    var hiddenField7 = document.createElement("input");
	    hiddenField7.setAttribute("type", "hidden");
	    hiddenField7.setAttribute("name", "csrfmiddlewaretoken");
	    hiddenField7.setAttribute("value", "{{ csrf_token }}");
	    form1.appendChild(hiddenField7);
            var hiddenField8 = document.createElement("input");
            hiddenField8.setAttribute("type", "hidden");
            hiddenField8.setAttribute("name", "updateType");
            hiddenField8.setAttribute("value", updateType);
            form1.appendChild(hiddenField8);
            var hiddenField9 = document.createElement("input");
            hiddenField9.setAttribute("type", "hidden");
            hiddenField9.setAttribute("name", "enabled");
            hiddenField9.setAttribute("value", document.getElementById('enabled').checked );
            form1.appendChild(hiddenField9);
	    document.body.appendChild(form1);
	    form1.submit();
	}
        function editUser(row) {
            ind = row - 1;
            var table = document.getElementById("EventTable").rows[ind];
            username = table.cells[1].innerHTML;
            console = document.getElementById('console' + row).checked;
            responder = document.getElementById('responder' + row).checked;
            sensor_admin = document.getElementById('sensor_admin' + row).checked;
            user_admin = document.getElementById('user_admin' + row).checked;
            server_admin = document.getElementById('server_admin' + row).checked;
            enabled = document.getElementById('enabled' + row).checked;
            user_field = document.getElementById('username');
            user_field.value = username;
            user_field.disabled = true;
            console_box = document.getElementById('console');
            console_box.checked = console;
            responder_box = document.getElementById('responder');
            responder_box.checked = responder;
            user_box = document.getElementById('user_admin');
            user_box.checked = user_admin;
            sensor_box = document.getElementById('sensor_admin');
            sensor_box.checked = sensor_admin;
            server_box = document.getElementById('server_admin');
            server_box.checked = server_admin;
            enabled_box = document.getElementById('enabled');
            enabled_box.disabled = false;
            enabled_box.checked = enabled;
            update_type = document.getElementById('updateType');
            update_type.value = 'editUser';
        }
	</script>
