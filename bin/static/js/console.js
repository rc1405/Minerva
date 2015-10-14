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
  
  // declare module functions
  app.clearSelected = function() {
    app.table.children('tr.minerva-active').removeClass('minerva-active');
    app.selected = [];
  };
  
  app.selectAll = function() {
    app.table.children('tr').not('.minerva-active').each(function(i, el) {
      var row = $(el);
      var id = row.data('id');
      
      row.addClass('minerva-active');
      app.selected.push(id);
    });
  };
  
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
  
  app.subAlerts = function(e) {
    var url = $(e.target).data('url');
    
    if (app.selected.length) {
      var comments = prompt('Enter Comments');
      
      if (comments) {
        var data = {
          events: app.selected,
          formType: app.form_type,
          comments: comments
        };
        
        $.ajax({
          method: 'POST',
          url: url,
          data: JSON.stringify(data),
          contentType: 'application/json',
          headers: {
            csrfmiddlewaretoken: app.csrf_token
          }
        }).done(function() {
          app.clearSelected();
        });
      }
    } else {
      alert('No events selected');
    }
  };
  
  app.clearAlerts = function() {
    if (app.selected.length) {
      var data = {
        events: app.selected,
        formType: app.form_type
      };
      
      $.ajax({
        method: 'POST',
        url: '/close_nc',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        }
      }).done(function() {
        app.clearSelected();
      });
    } else {
      alert('No events selected');
    }
  };
  
  app.getAlertFlow = function() {
    if (app.selected.length) {
      if (app.selected.length <= 5) {
        var data = {
          events: app.selected,
          formType: app.form_type
        };
        
        $.ajax({
          method: 'POST',
          url: '/get_alert_flow',
          data: JSON.stringify(data),
          contentType: 'application/json',
          headers: {
            csrfmiddlewaretoken: app.csrf_token
          }
        }).done(function(html) {
          app.clearSelected();
          var wind = window.open('', '_blank');
          wind.document.write(html);
        });
      } else {
        alert('Can only request transcript for up to five events at a time');
      }
    } else {
      alert('No events selected');
    }
  };
  
  app.getOneAlertFlow = function(e) {
    var row = $(e.currentTarget).parent();
    var id = row.data('id');
    var data = {
      events: [id],
      formType: app.form_type
    };
    
    $.ajax({
      method: 'POST',
      url: '/get_alert_flow',
      data: JSON.stringify(data),
      contentType: 'application/json',
      headers: {
        csrfmiddlewaretoken: app.csrf_token
      }
    }).done(function(html) {
      var wind = window.open('', '_blank');
      wind.document.write(html);
    });
        
    e.stopPropagation();
  };
  
  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.table.on('click', '.minerva-flow', app.getOneAlertFlow);
  app.nav.on('click', '.minerva-subalert', app.subAlerts);
  app.nav.find('#clear_alerts').click(app.clearAlerts);
  app.nav.find('#unselect').click(app.clearSelected);
  app.nav.find('#highlight').click(app.selectAll);
  app.nav.find('#get_flow').click(app.getAlertFlow);
  
})(jQuery, minerva.console);
