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
	var selected = [];
	var index;
	function startTrack(x) {
	    var cur_color = x.getAttribute("bgcolor");
	    if (cur_color === "gray" ) {
		for ( index = 0; index < selected.length; index++) {
		    if ( selected[index] === x.cells[0].innerHTML) {
			selected.splice(index, 1);
			break;
		    }
		}
	    	switch(x.cells[11].innerHTML) {
		    case "4":
			x.setAttribute("bgcolor", "red");
			break;
		    case "3":
			x.setAttribute("bgcolor", "orange");
			break;
		    case "2":
			x.setAttribute("bgcolor", "yellow");
			break;
		    case "1":
			x.setAttribute("bgcolor", "green");
			break;
		}
	     } else {
		selected.push(x.cells[0].innerHTML);
	    	x.setAttribute("bgcolor", "gray");
	    }
	}
	function clearSelected() {
	    for ( index = 0; index < selected.length; index++) {
		//remove row from table
		selected.splice(index, 1);
	    }
	}
        function subAlerts (postTo) {
	    var comments = prompt("Enter Comments");
	    if ( comments != null) {
                if ( selected.length === 0) {
                    alert("No Events Selected");
                } else {
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
		    hiddenField1.setAttribute("value", "{{ form }}" );
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
                    document.body.appendChild(form);
                    form.submit();
                    clearSelected();
                }
	    }
        }
	function ClearAlerts_nc () {
	    if ( selected.length === 0) {
		alert("No Events Selected");
	    } else {
	        var form = document.createElement("form");
	        form.setAttribute("method", "post");
	        form.setAttribute("action", "/close_nc");
		form.setAttribute("onsubmit", "return");
	        var hiddenField = document.createElement("input");
	        hiddenField.setAttribute("type", "hidden");
	        hiddenField.setAttribute("name", "events");
	        hiddenField.setAttribute("value", selected);
	        form.appendChild(hiddenField)
		var hiddenField1 = document.createElement("input");
		hiddenField1.setAttribute("type", "hidden");
		hiddenField1.setAttribute("name", "formType");
		hiddenField1.setAttribute("value", "{{ form }}" );
		form.appendChild(hiddenField1);
	        var hiddenField2 = document.createElement("input");
	        hiddenField2.setAttribute("type", "hidden");
	        hiddenField2.setAttribute("name", "csrfmiddlewaretoken");
	        hiddenField2.setAttribute("value", "{{ csrf_token }}");
	        form.appendChild(hiddenField2)
	        document.body.appendChild(form);
	        form.submit();
	        clearSelected();
	    }
	}
	function unselectAll () {
	    var table = document.getElementById("EventTable");
	    for (var i = 0, row; row = table.rows[i]; i++) {
		var cur_color = row.getAttribute("bgcolor");
		if (cur_color === "gray" ) {
		    startTrack(row);
                 }
	    }
	}
        function highlightAll () {
            var table = document.getElementById("EventTable");
            for (var i = 0, row; row = table.rows[i]; i++) {
                var cur_color = row.getAttribute("bgcolor");
                if ( cur_color !== "grey" ) {
                    //startTrack(row);
                    if ( cur_color !== null ) {
                        selected.push(row.cells[0].innerHTML);
                        row.setAttribute("bgcolor", "gray");
                    }
                }
            }
        }
        function getAlertFlow () {
            if ( selected.length === 0) {
                alert("No Events Selected");
	    } else if ( selected.length > 5 ) {
		alert("Can only request transcript for up to five events at a time");
            } else {
	        for ( index = 0; index < selected.length; index++) {
                    var form = document.createElement("form");
		    form.setAttribute("id", "getFlowForm");
                    form.setAttribute("method", "post");
                    form.setAttribute("action", "/get_alert_flow");
		    form.setAttribute("target", selected[index]);
                    var hiddenField = document.createElement("input");
                    hiddenField.setAttribute("type", "hidden");
                    hiddenField.setAttribute("name", "ID");
                    hiddenField.setAttribute("value", selected[index]);
                    form.appendChild(hiddenField)
                    var hiddenField1 = document.createElement("input");
                    hiddenField1.setAttribute("type", "hidden");
                    hiddenField1.setAttribute("name", "formType");
                    hiddenField1.setAttribute("value", "{{ form }}" );
                    form.appendChild(hiddenField1);
                    var hiddenField2 = document.createElement("input");
                    hiddenField2.setAttribute("type", "hidden");
                    hiddenField2.setAttribute("name", "csrfmiddlewaretoken");
                    hiddenField2.setAttribute("value", "{{ csrf_token }}");
                    form.appendChild(hiddenField2);
                    window.open('',selected[index]);
                    //document.body.appendChild(form);
                    form.submit();
                }
            }
        }
        function getOneAlertFlow(row) {
            ind = row - 1;
            var table = document.getElementById("EventTable").rows[ind];
            var form = document.createElement("form");
            form.setAttribute("id", "getFlowForm");
            form.setAttribute("method", "post");
            form.setAttribute("action", "/get_alert_flow");
            form.setAttribute("target", table.cells[0].innerHTML);
            var hiddenField = document.createElement("input");
            hiddenField.setAttribute("type", "hidden");
            hiddenField.setAttribute("name", "ID");
            hiddenField.setAttribute("value", table.cells[0].innerHTML);
            form.appendChild(hiddenField)
            var hiddenField1 = document.createElement("input");
            hiddenField1.setAttribute("type", "hidden");
            hiddenField1.setAttribute("name", "formType");
            hiddenField1.setAttribute("value", "{{ form }}" );
            form.appendChild(hiddenField1);
            var hiddenField2 = document.createElement("input");
            hiddenField2.setAttribute("type", "hidden");
            hiddenField2.setAttribute("name", "csrfmiddlewaretoken");
            hiddenField2.setAttribute("value", "{{ csrf_token }}");
            form.appendChild(hiddenField2);
            window.open('',table.cells[0].innerHTML);
            form.submit();
        }
	</script>
