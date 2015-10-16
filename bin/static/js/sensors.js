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

minerva.console = {};

(function ($, app) {
  // declare module properties
  app.selected = [];  
  app.nav = $('nav');
  app.table = $('#event_table tbody');
  app.form_type = $('#form_type').val();
  app.csrf_token = $('#csrf_token').val();
  
  app.startTrack = function(e) {
    var row = $(e.currentTarget);
    var id = row.data('id');
    
    if (row.hasClass('minerva-active')) {
      row.removeClass('minerva-active');
      app.selected.splice(app.selected.indexOf(id), 1);
    } else {
      row.addClass('minerva-active');
      app.selected.push(id);
    }
    
    e.stopPropagation();
  };
  
  app.subSensor = function(s) {
    var sensor_action = $(s.target).data('action');
    if (app.selected.length) {
      var data = {
        sensors: app.selected,
        formType: app.form_type,
        action: sensor_action
      };
      
      $.ajax({
        method: 'POST',
        url: '/sensors',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        },
        success: function (data) {
            document.open();
            document.write(data);
            document.close();
        },
      });
    } else {
      alert('No Sensors selected');
    }
  };
  
  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.nav.on('click', '.minerva-sensor', app.subSensor);
  
})(jQuery, minerva.console);
