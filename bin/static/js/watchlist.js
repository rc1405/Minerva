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

minerva.watchlist = {};

(function ($, app) {
  // declare module properties
  app.selected = [];  
  app.nav = $('nav');
  app.table = $('#event_table tbody');
  app.application = $('#current_status');
  //app.form_type = $('#form_type').val();
  app.csrf_token = $('#csrf_token').val();
  
  app.clearSelected = function() {
    app.table.children('tr.minerva-active').removeClass('minerva-active');
    app.selected = [];
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

  app.WatchlistChanges = function(e) {
    var action = $(e.target).data('action');

    if (app.selected.length) {

      var data = {
        events: app.selected,
        req_type: action,
      };

      $.ajax({
        method: 'POST',
        url: '/watchlist',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        },
        success: function (response) {
          if (response != 'None') {
            alert(response);
          };
          location='/watchlist';
        },
      });
    } else {
      alert('No Items selected');
    };
  };
  
  app.addWatchlist = function() {
    var data = {
         'type': $('#watchlist_select').val(),
         'req_type': 'new',
         'criteria': $('#watchlist_item').val(),
         'priority': $('#priority').val(),
    }
    $.ajax({
      method: 'POST',
      url: '/watchlist',
      data: JSON.stringify(data),
      contentType: 'application/json',
      headers: {
        csrfmiddlewaretoken: app.csrf_token
      },
      success: function (response) {
        if (response) {
          alert(response);
        };
        location='/watchlist';
      },
    });
  };

  // bind events
  app.table.on('click', 'tr', app.startTrack);
  app.nav.on('click', '.minerva-watchlist', app.WatchlistChanges);
  $('#minerva-addWatchlist').click(app.addWatchlist);
  
})(jQuery, minerva.watchlist);
