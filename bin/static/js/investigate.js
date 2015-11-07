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

minerva.investigate = {};

(function($, app) {
  app.nav = $('nav');
  app.tabs = $('#tabs');
  app.tab_content = $('#tab_content');
  app.form_type = 'investigate'
  app.csrf_token = $('#csrf_token').val();

  app.checkActiveTabs = function() {
    var tab_count = app.tabs.find('.hidden').length;
    var total_tab_count = app.tabs.children('li').length;
    if (tab_count >= total_tab_count) {
      return true;
    } else {
      return false;
    };
  };

  app.ActivateNextTab = function () {
    app.tabs.children('li').not('.hidden').first().addClass('active');
    app.tab_content.children('div').not('.hidden').first().addClass('active');
  };

  app.subAlerts = function(e) {
    var url = $(e.target).data('url');    
    var comments = prompt('Enter Comments');
    
    if (comments) {
      var active_event = app.tabs.find('.active')
      var data = {
        events: [active_event.data('id')], 
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
      }).done(function(data) {
        if (url != '/comment') {
          active_event.removeClass('active');
          active_event.addClass('hidden');
          var active_tab = app.tab_content.find('.active');
          active_tab.removeClass('active');
          active_tab.addClass('hidden');
          app.ActivateNextTab();
          opener.location.reload();
        }
        if (app.checkActiveTabs()) {
          document.open();
          document.write(data);
          document.close();
        };
        });
    };
  };

  app.getAlertPCAP = function() {
    var active_event = app.tabs.find('.active').data('id');
      var data = {
        events: [active_event],
        formType: app.form_type
      };
      $.ajax({
        method: 'POST',
        url: '/get_pcap',
        data: JSON.stringify(data),
        contentType: 'application/json',
        headers: {
          csrfmiddlewaretoken: app.csrf_token
        }
      }).done(function(html) {
        var wind = window.open('data:application/download', '_blank');
        wind.document.write(html);
      });
  };
  
  app.nav.on('click', '.minerva-subalert', app.subAlerts);
  app.nav.find('#get_pcap').click(app.getAlertPCAP);
  
})(jQuery, minerva.investigate);
