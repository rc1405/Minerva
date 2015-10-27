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
var minerva = minerva || {};

minerva.alerts = {};

(function($, app) {
  app.form = $('#search');
  
  function search_alerts(e) {
    e.preventDefault();
    
    var data = $(e.target).serialize();
    
    $.get('/alerts', data).fail(function() {
      alert('Search request failed');
    });
  }
  
  app.form.submit(search_alerts);
  
  $("#dt_start").DateTimePicker({dateTimeFormat: "MM-dd-yyyy hh:mm:ss"});
  $("#dt_stop").DateTimePicker({dateTimeFormat: "MM-dd-yyyy hh:mm:ss"});
  
})(jQuery, minerva.alerts);