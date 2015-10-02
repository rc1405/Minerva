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
	    	switch(x.cells[5].innerHTML) {
		    case "_DENIED":
			x.setAttribute("bgcolor", "red");
			break;
		    case "CERT_CHANGED":
			x.setAttribute("bgcolor", "orange");
			break;
		    case "NOT_APPROVED":
			x.setAttribute("bgcolor", "yellow");
			break;
		    case "APPROVED":
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
	function subChanges (action) {
	    if ( selected.length === 0) {
		alert("No Events Selected");
	    } else {
	        var form = document.createElement("form");
	        form.setAttribute("method", "post");
	        form.setAttribute("action", "/sensors");
	        var hiddenField = document.createElement("input");
	        hiddenField.setAttribute("type", "hidden");
	        hiddenField.setAttribute("name", "sensors");
	        hiddenField.setAttribute("value", selected);
	        form.appendChild(hiddenField);
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
                var hiddenField3 = document.createElement("input");
                hiddenField3.setAttribute("type", "hidden");
                hiddenField3.setAttribute("name", "action");
                hiddenField3.setAttribute("value", action);
                form.appendChild(hiddenField3);
	        document.body.appendChild(form);
	        form.submit();
	        clearSelected();
	    }
	}
	</script>
