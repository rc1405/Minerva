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
	function refreshParent() {
	    window.opener.location.reload();
	}
        function subAlerts (postTo) {
	    var selected = [];
	    selected.push("{{ alert_id }}");
	    var comments = prompt("Enter Comments");
	    if ( comments != null) {
                var form = document.createElement("form");
                form.setAttribute("method", "post");
                form.setAttribute("action", postTo);
                var hiddenField = document.createElement("input");
                hiddenField.setAttribute("type", "hidden");
                hiddenField.setAttribute("name", "events");
                hiddenField.setAttribute("value", selected);
                form.appendChild(hiddenField)
		var hiddenField1 = document.createElement("input");
		hiddenField1.setAttribute("type", "hidden");
		hiddenField1.setAttribute("name", "formType");
		hiddenField1.setAttribute("value", "AlertFlow" );
		form.appendChild(hiddenField1);
                var hiddenField2 = document.createElement("input");
                hiddenField2.setAttribute("type", "hidden");
                hiddenField2.setAttribute("name", "csrfmiddlewaretoken");
                hiddenField2.setAttribute("value", "{{ csrf_token }}");
                form.appendChild(hiddenField2)
		var hiddenField3 = document.createElement("input");
		hiddenField3.setAttribute("type", "hidden");
		hiddenField3.setAttribute("name", "comments");
		hiddenField3.setAttribute("value", comments);
		form.appendChild(hiddenField3)
		//var hiddenField4 = document.createElement("input");
		//hiddenField4.setAttribute("type", "hidden");
		//hiddenField4.setAttribute("name", "AlertFlow");
		//hiddenField4.setAttribute("value", "stuff");
		//form.appendChild(hiddenField4);
                document.body.appendChild(form);
		refreshParent();
                form.submit();
		//refreshParent();
		//close();
	    }
        }
	</script>
