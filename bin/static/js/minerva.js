/*
    Copyright (C) 2017  Ryan M Cote.

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
  app.event_div = $(".minerva-alerts");
  app.d3 = window.d3;
  app.mustache = window.Mustache;
  app.ws = "";
  app.severity_class = ["", "", "minerva-alert-low", "minerva-alert-medium", "minerva-alert-high", "minerva-alert-high"];
  app.events = [];
  app.page_count = 1;
  app.per_page = 5;
  app.cur_page = 1;
  app.severityClass = ["", "", "minerva-alert-low", "minerva-alert-medium", "minerva-alert-high", "minerva-alert-high"];

  app.lindex = function () {
    if ( $("#MinervaEvents").children('div').length == 0 ) {
      return 1
    } else {
      return parseInt($("#MinervaEvents")
        .children('div')
        .last()
        .attr('id')
        .replace('row','')) + 1;
    };
  };

  app.newElement = function(e) {
    var ne = document.createElement(e);
    return $(ne)
  };

  app.hidePie = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent().parent().children('.minerva-body').last();
    ediv.children('div').removeClass("hidden");
    ediv.children('.minerva-bar').addClass("hidden");
    ediv.children('.minerva-table').addClass("hidden");
  };

  app.hideBar = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent().parent().children('.minerva-body').last();
    ediv.children('div').removeClass("hidden");
    ediv.children('.minerva-pie').addClass("hidden");
    ediv.children('.minerva-table').addClass("hidden");
  };

  app.hideTab = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent().parent().children('.minerva-body').last();
    ediv.children('div').removeClass("hidden");
    ediv.children('.minerva-pie').addClass("hidden");
    ediv.children('.minerva-bar').addClass("hidden");
  };

  app.refreshCharts = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent().parent();
    var data = {
      "session_id": $("#minerva_token").val(),
      "chart": ediv.attr('id'),
      "action": "refresh_chart"
    };
    app.ws.send(JSON.stringify(data));
    alert(JSON.stringify(data));
  };

  app.CloseEvent = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "close"
    };
    app.ws.send(JSON.stringify(data));
    //open modal
    //set hidden values in modal
  };

  app.CloseModal = function() {
    // get data from modal form
    // close modal
    // spinning modal
    // send to websocket
  };

  app.Investigate = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "investigate"
    };
    app.ws.send(JSON.stringify(data));

    // spinning modal
    // send to websocket
    // websocket to open investigate modal
  };

  app.AssignEvent = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "assign"
    };
    app.ws.send(JSON.stringify(data));

    // spinning modal
    // send to websocket
    // websocket to update assign box
  };

  app.RequestPCAP = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "pcap"
    };
    app.ws.send(JSON.stringify(data));

    // spinning wheel
    // send to websocket
    // alert modal to acknowledge request was submited
    // update pcap active request count
    // websocket to update ready request count
    // websocket to alert modal pcap ready or timeout/error
  };

  app.Escalate = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "escalate"
    };
    app.ws.send(JSON.stringify(data));

    // escalate modal
    // set hidden values
    // spinning wheel 
    // send to websocket
    // websocket to alert modal results
    // websocket to update console
  };

  app.CommentEvent = function(e) {
    var ediv = $(e.currentTarget).parent().parent().parent();
    var uuids = ediv.data('uuids').split(',');

    var data = {
      "session_id": $("#minerva_token").val(),
      "uuids": uuids,
      "action": "comment"
    };
    app.ws.send(JSON.stringify(data));

    // comment modal
    // spinning modal
    // send to websocket
    // websocket to alert modal results
  };

  app.changePage = function() {
    var eventdiv = $('#MinervaEvents');
    var eventpager = $('#EventPager');
    eventdiv.children('div').addClass('hidden');
    var startAt = (app.cur_page-1) * app.per_page;
    var endAt = startAt + app.per_page;
    eventdiv.children('div').slice(startAt, endAt).removeClass('hidden');


    app.page_count = Math.ceil(app.events.length/app.per_page);

    eventpager.children().slice(1).remove();

    var start_page = app.cur_page - 2;
    var end_page = app.cur_page + 2;
    if (start_page < 1 && end_page <= 5 && app.page_count >= 5 ) {
      start_page = 1;
      end_page = 5;
    } else if (start_page < 1 && end_page < 5 ) {
      start_page = 1;
      end_page = app.page_count;
    } else if (end_page > app.page_count && end_page > 5) {
      start_page = app.page_count - 5;
      end_page = app.page_count;
    } else if (end_page < 5 && app.page_count < 5) {
      start_page = 1;
    } else if (end_page > app.page_count) {
      end_page = app.page_count;
    };

    while (start_page <= end_page) {
      var new_pager = app.newElement('li');
      new_pager.addClass('minerva-pager');
      if (start_page == app.cur_page) {
        new_pager.addClass('active');
        // TODo differetn add
      };
      new_pager.attr("data-value", start_page);
      var new_pager_a = app.newElement('a');
      new_pager_a.html(start_page);
      new_pager_a.attr('href','#');
      new_pager.append(new_pager_a);
      eventpager.append(new_pager);
      start_page = start_page + 1;
    };

    var new_pager = app.newElement('li');
    new_pager.addClass('minerva-pager');
    new_pager.attr("data-value", "next");
    var new_pager_a = app.newElement('a');
    new_pager_a.attr('href',"#");
    new_pager_a.attr('aria-label','Next');
    var new_pager_span = app.newElement('span');
    new_pager_span.html('&raquo;');
    new_pager_span.attr('aria-hidden','true');
    new_pager_a.append(new_pager_span);
    new_pager.append(new_pager_a);
    eventpager.append(new_pager);

  };

  app.changeSize = function(e) {
    var pagesizer = $("#PageSizer");
    var ediv = $(e.currentTarget);
    var eval = ediv.data("value");
    if (eval == 'all') {
      app.per_page = app.events.length + 1;
    } else {
      app.per_page = parseInt(eval);
    };

    pagesizer.children('li').remove();

    var page_values = [5,15,25,"all"];

    $.each(page_values, function(i, v) {
      var new_li = app.newElement('li');
      new_li.attr('data-value', v);
      if (v == app.per_page || ( v == 'all' && app.per_page > 25 )) {
        new_li.addClass('active');
        var new_span_1 = app.newElement('span');
        new_span_1.html(v);
        var new_span_2 = app.newElement('span');
        new_span_2.addClass('sr-only');
        new_span_2.html("(current)");
        new_span_1.append(new_span_2);
        new_li.append(new_span_1);
      } else {
        new_li.addClass('minerva-psize');
        var new_a = app.newElement('a');
        new_a.attr('href','#');
        new_a.html(v);
        new_li.append(new_a);
      };
      pagesizer.append(new_li);
    });
    
    app.changePage();
  };

  app.pagerChange = function(e) {
    var eventpager = $('#EventPager');
    var ediv = $(e.currentTarget);
    var cur_page = ediv.data("value");
    if (cur_page == 'prev') {
      app.cur_page = app.cur_page - 3;
      if (app.cur_page < 1) {
        app.cur_page = 1;
      };
    } else if (cur_page == 'next') {
      app.cur_page = app.cur_page + 3;
      if (app.cur_page > app.page_count) {
        app.cur_page = app.page_count;
      };
    } else {
      app.cur_page = parseInt(cur_page);
    };
    app.changePage();
  };

  app.startListener = function() {
    var websocket = 'wss://' + window.location.hostname + '/ws';
    if (window.WebSocket) {
      app.ws = new WebSocket(websocket);
    } else if (window.MozWebSocket) {
      app.ws = new MozWebSocket(websocket);
    };

    $(window).on('beforeunload', function () {
      app.ws.close();
    });

    app.ws.onopen = function() {
      //alert("Websocket is a go");
      data = {
        "session_id": $("#minerva_token").val(),
        "action": "form",
        "form": $("#form_type").val()
      };
      if (app.ws.readyState == 1) {
        app.ws.send(JSON.stringify(data));
      };
    };

    app.ws.onmessage = function(evt) {
      //alert(evt.data);
      var data = JSON.parse(evt.data);
      switch(data['action']) {
        case "new_events":
          //insert new events here;
          var eventdiv = $('#MinervaEvents');
          var eventpager = $('#EventPager');
          eventdiv.children('div').remove();
          var event_count = 0;
          var alertTemplate = $("#alertTemplate").html();
          app.events = [];

          $.each(data['events'], function(i, v) {
            v['index'] = i;
            v['severity_class'] = app.severityClass[v['severity']];
            if (event_count >= app.per_page ) {
              v['hidden'] = true;
            } else {
              v['hidden'] = false;
            };

            v['event_count'] = event_count;
            v['per_page'] = app.per_page;
            //alert(JSON.stringify(v));
            if ( $('.sighash-' + v['sig_hash']).length > 0 ) {
              //alert(JSON.stringify(v));
              var erow = $('.sighash-' + v['sig_hash']).first();
              var uuids = erow.data("uuids");
              uuids = uuids + ',' + v['ids'];
              var count_div = erow.children('div').first().children('.minerva-count').first();
              var count = parseInt(count_div.data('count'));
              count = count + v['count'];
              count_div.attr('data-count', count);
              count_div.html("<b>Count: </b>" + count);

            } else {
              var new_alert_div = app.mustache.to_html(alertTemplate, v);
              //var new_alert_div = app.processEvents(v);
              //if (event_count >= app.per_page ) {
                //new_alert_div.addClass('hidden');
              //};
              //add new alert div to document
              eventdiv.append(new_alert_div);
              app.events.push(new_alert_div);
              event_count = event_count + 1;

            };
          });

          var numPages = Math.ceil(app.events.length/app.per_page);

          while (numPages > 1 && app.page_count < numPages && app.page_count < 5 ) {
            app.page_count = app.page_count + 1;
            var new_pager = app.newElement('li');
            new_pager.addClass('minerva-pager');
            new_pager.attr("data-value", app.page_count);
            var new_pager_a = app.newElement('a');
            new_pager_a.html(app.page_count);
            new_pager_a.attr('href','#');
            new_pager.append(new_pager_a);
            eventpager.append(new_pager);
          };
          app.page_count = numPages;

          var new_pager = app.newElement('li');
          new_pager.addClass('minerva-pager');
          new_pager.attr("data-value", "next");
          var new_pager_a = app.newElement('a');
          new_pager_a.attr('href',"#");
          new_pager_a.attr('aria-label','Next');
          var new_pager_span = app.newElement('span');
          new_pager_span.html('&raquo;');
          new_pager_span.attr('aria-hidden','true');
          new_pager_a.append(new_pager_span);
          new_pager.append(new_pager_a);
          eventpager.append(new_pager);
          break;
        case "events":
          if ( $('.sighash-' + data['sig_hash']).length > 0 ) {
            //alert(JSON.stringify(v));
            var erow = $('.sighash-' + data['sig_hash']).first();
            var uuids = erow.data("uuids");
            uuids = uuids + ',' + data['ids'];
            var count_div = erow.children('div').first().children('.minerva-count').first();
            var count = parseInt(count_div.data('count'));
            count = count + data['count'];
            count_div.attr('data-count', count);
            count_div.html("<b>Count: </b>" + count);
          } else {
            var eventdiv = $('#MinervaEvents');
            var new_alert_div = app.processEvents(data['event']);
            //add new alert div to document
            eventdiv.append(new_alert_div);
          };
          break;
        case "refresh_chart":
            //alert('chart refresh');
            //alert(evt.data);
            //var bar_div = app.createBar(app.d3, data['data'], 'color_code');
            var pie_div = app.createPie(app.d3, data['data'], 'color_code');
            //var tab_div = app.createTable(data['data']);
            var ip_charts = $($("#" + data['chart']).children('.minerva-body').first());
            ip_charts.children('div').remove();
            //ip_charts.append(bar_div);
            ip_charts.append(pie_div);
            //ip_charts.append(tab_div);
            //app.createBar(app.d3, event_types, '#event_type');
            break;
        case "investigate":
            alert('investigate, rawr');
            var inv_div = app.processInvestigate(data);
            alert(inv_div);
            $("#investigateModalBody").html(''); //children().remove();
            $("#investigateModalBody").append(inv_div);
            $("#investigateModal").modal('show');
            alert('done');
            // stop spinning modal
            // show investigate modal
            break;
        /*
        case "close":
          //alert("should be deleted");
          if (!$("#" + data.uuid).length == 0) {
            //alert('deleted');
            app.deleteEvent(data.uuid);
          };
          break;
        case "assign":
          var arow = $("#user-row_" + data.uuid);
          arow.html(data.username);
          $('#' + data.uuid).removeClass("watchuser-Unassigned");
          $('#' + data.uuid).addClass("watchuser-" + data.sso);
          break;
        case "new":
          if (app.form_type == 'console') {
            app.processEvent(data);
          } else if ($("#" + data.uuid).length > 0) {
            app.deleteEvent(data.uuid);
          };
          break;
        */
      };
    };
  };

  app.processEvents = function(v) {
    //base alert div
    var new_alert_div = app.newElement('div');
    new_alert_div.addClass("row minerva-alert " + app.severity_class[v['severity']] + " sighash-" + v['sig_hash']);
    new_alert_div.attr('id', 'row' + app.lindex());
    new_alert_div.attr('data-uuids',v['ids']);

    //top row div
    var top_row_div = app.newElement('div');

    //time column
    var time_div = app.newElement('div');
    time_div.addClass("col-md-2");
    var time_b = app.newElement('b')
    time_b.html('Timestamp: ')
    time_div.append(time_b);
    time_div.append(v['timestamp']);
    top_row_div.append(time_div);

    //sensor column
    var sensor_div = app.newElement('div');
    sensor_div.addClass("col-md-2");
    var sensor_b = app.newElement('b');
    sensor_b.html('Sensor: ');
    sensor_div.append(sensor_b);
    sensor_div.append(v['sensor']);
    top_row_div.append(sensor_div);

    //severity column
    var sev_div = app.newElement('div');
    sev_div.addClass("col-md-1");
    var sev_b = app.newElement('b');
    sev_b.html('Severity: ');
    sev_div.append(sev_b);
    sev_div.append(v['severity']);
    top_row_div.append(sev_div);

    //count column
    var count_div = app.newElement('div');
    count_div.addClass("col-md-1 minerva-count");
    count_div.attr("data-count", v['count']);
    var count_b = app.newElement('b');
    count_b.html('Count: ');
    count_div.append(count_b);
    count_div.append(v['count']);
    top_row_div.append(count_div);

    //icon column
    var icon_div = app.newElement('div');
    icon_div.addClass("col-md-6 text-right minerva-chart-icons");
    icon_div.addClass("minerva-alert-icons");
    //assign
    var assign_a = app.newElement('a');
    assign_a.attr('href','#');
    assign_a.addClass("minerva-assign minerva-alert-icon");
    assign_a.attr('data-toggle','tooltip');
    assign_a.attr('data-placement','left');
    assign_a.attr('title','Assign to me');
    var assign_span = app.newElement('span');
    assign_span.addClass("glyphicon glyphicon-user");
    assign_a.append(assign_span);
    icon_div.append(assign_a);
    //investigate
    var investigate_a = app.newElement('a');
    investigate_a.attr('href','#');
    investigate_a.addClass("minerva-investigate minerva-alert-icon");
    investigate_a.attr('data-toggle','tooltip');
    investigate_a.attr('data-placement','left');
    investigate_a.attr('title','More Details');
    var investigate_span = app.newElement('span');
    investigate_span.addClass("glyphicon glyphicon-search");
    investigate_a.append(investigate_span);
    icon_div.append(investigate_a);
    //pcap
    var pcap_a = app.newElement('a');
    pcap_a.attr('href','#');
    pcap_a.addClass("minerva-pcap minerva-alert-icon");
    pcap_a.attr('data-toggle','tooltip');
    pcap_a.attr('data-placement','left');
    pcap_a.attr('title','Request PCAP');
    var pcap_span = app.newElement('span');
    pcap_span.addClass("glyphicon glyphicon-download-alt");
    pcap_a.append(pcap_span);
    icon_div.append(pcap_a);
    //escalate
    var escalate_a = app.newElement('a');
    escalate_a.attr('href','#');
    escalate_a.addClass("minerva-escalate minerva-alert-icon");
    escalate_a.attr('data-toggle','tooltip');
    escalate_a.attr('data-placement','left');
    escalate_a.attr('title','Escalate');
    var escalate_span = app.newElement('span');
    escalate_span.addClass("glyphicon glyphicon-circle-arrow-up");
    escalate_a.append(escalate_span);
    icon_div.append(escalate_a);
    //close
    var close_a = app.newElement('a');
    close_a.attr('href','#');
    close_a.addClass("minerva-close minerva-alert-icon");
    close_a.attr('data-toggle','tooltip');
    close_a.attr('data-placement','left');
    close_a.attr('title','Close');
    var close_span = app.newElement('span');
    close_span.addClass("glyphicon glyphicon-remove");
    close_a.append(close_span);
    icon_div.append(close_a);
    //comment
    var comment_a = app.newElement('a');
    comment_a.attr('href','#');
    comment_a.addClass("minerva-comment minerva-alert-icon");
    comment_a.attr('data-toggle','tooltip');
    comment_a.attr('data-placement','left');
    comment_a.attr('title','Comment');
    var comment_span = app.newElement('span');
    comment_span.addClass("glyphicon glyphicon-comment");
    comment_a.append(comment_span);
    icon_div.append(comment_a);
    top_row_div.append(icon_div);

    //Add top row to new alert div
    new_alert_div.append(top_row_div);

    //Second row div
    var mid_row_div = app.newElement('div');
    
    //Src Ip column
    var sip_div = app.newElement('div');
    sip_div.addClass("col-md-2");
    var sip_b = app.newElement('b');
    sip_b.html('Src IP: ');
    sip_div.append(sip_b);
    sip_div.append(v['src_ip']);
    mid_row_div.append(sip_div);

    //Src Port column
    var spt_div = app.newElement('div');
    spt_div.addClass("col-md-2");
    var spt_b = app.newElement('b');
    spt_b.html('Src Port: ');
    spt_div.append(spt_b);
    spt_div.append(v['src_port']);
    mid_row_div.append(spt_div);

    //Proto column
    var pro_div = app.newElement('div');
    pro_div.addClass("col-md-1");
    var pro_b = app.newElement('b');
    pro_b.html('Proto: ');
    pro_div.append(pro_b);
    pro_div.append(v['proto']);
    mid_row_div.append(pro_div);

    //signature column
    var sig_div = app.newElement('div');
    sig_div.addClass("col-md-7");
    var sig_b = app.newElement('b');
    sig_b.html("Signature: ");
    sig_div.append(sig_b);
    sig_div.append(v['signature']);
    mid_row_div.append(sig_div);

    //Add mid row to new alert div
    new_alert_div.append(mid_row_div);

    //bottom row div
    var bot_row_div = app.newElement('div');
     
    //Dest IP column
    var dip_div = app.newElement('div');
    dip_div.addClass("col-md-2");
    var dip_b = app.newElement('b');
    dip_b.html('Dst IP: ');
    dip_div.append(dip_b);
    dip_div.append(v['dest_ip']);
    bot_row_div.append(dip_div);

    //Dst Port Column
    var dpt_div = app.newElement('div');
    dpt_div.addClass("col-md-2");
    var dpt_b = app.newElement('b');
    dpt_b.html('Dst Port: ');
    dpt_div.append(dpt_b);
    dpt_div.append(v['dest_port']);
    bot_row_div.append(dpt_div);

    //add empty div
    var emp_div = app.newElement('div');
    emp_div.addClass("col-md-1");
    bot_row_div.append(emp_div);

    //category column
    var cat_div = app.newElement('div');
    cat_div.addClass("col-md-5");
    var cat_b = app.newElement('b');
    cat_b.html('Category: ');
    cat_div.append(cat_b);
    cat_div.append(v['category']);
    bot_row_div.append(cat_div);

    //sid column
    var sid_div = app.newElement('div');
    sid_div.addClass("col-md-1");
    var sid_b = app.newElement('b');
    sid_b.html('SID: ');
    sid_div.append(sid_b);
    sid_div.append(v['sid'])
    bot_row_div.append(sid_div);

    //rev column
    var rev_div = app.newElement('div');
    rev_div.addClass("col-md-1");
    var rev_b = app.newElement('b');
    rev_b.html("Rev: ");
    rev_div.append(rev_b);
    rev_div.append(v['rev']);
    bot_row_div.append(rev_div);

    //add bottom row to new alert div
    new_alert_div.append(bot_row_div);

    return new_alert_div
       
  };

  app.processInvestigate = function(data) {
    //base alert div
    var new_investigate_div = app.newElement('div');
    new_investigate_div.addClass("container-fluid");

    var new_alert_table = app.newElement('div');

    $.each(data['events']['alerts'], function (i, v) {
      var new_alert_div = app.processEvents(v);
      new_alert_table.append(new_alert_div);
      //append hidden row with packet data
      //var hidden_alert_div = app.processPacket(v);
    });

    //var new_flow_table = app.newElement('div');
  
    //$.each(data['flow'], function(i, v) {
        //var new_flow_div = app.processFlow(v);
        //new_flow_table.append(new_flow_div);
    //})

    //var new_dns_table = app.newElement('div');

    //$.each(data['dns'], function (i, v) {
      //var new_dns_div = app.processDns(v);
      //new_dns_table.append(new_dns_div);
    //});
    new_investigate_div.append(new_alert_table);
    return new_investigate_div;
  };

  app.createPie = function(d3, dataset, chart) {

    var new_pie_div =  document.createElement('div');
    $(new_pie_div).addClass("container-fluid");
    var new_chart_div =  document.createElement('div');
    $(new_chart_div).addClass("col-md-6");
    var new_legend_div =  document.createElement('div');
    $(new_legend_div).addClass("col-md-6");
    var new_tooltip_div =  document.createElement('div');
    $(new_tooltip_div).addClass("col-md-12");


    'use strict';
    var width = 225;
    var height = 225;
    var radius = Math.min(width, height) / 2;
    var donutWidth = 50;
    var legendRectSize = 18;
    var legendSpacing = 4;

    if (chart == '#priority') {
      var color = d3.scaleOrdinal()
        .domain(["high", "normal"])
        .range(["rgb(250, 212, 210)", "rgb(226, 250, 210)"]);
   } else if (chart == '#location') {
      var color = d3.scaleOrdinal()
        .domain(["aws", "enterprise"])
        .range(["rgb(210, 141, 239)", "rgb(43, 202, 216)"]);
   } else if (chart == '#event_type') {
      var color = d3.scaleOrdinal(d3.schemeCategory20b);
   } else {
      var color = d3.scaleOrdinal(d3.schemeCategory20);
   };

    var svg = d3.select(new_chart_div)
      .append('svg')
      .attr('width', width)
      .attr('height', height)
      .append('g')
      .attr('transform', 'translate(' + (width / 2) +
        ',' + (height / 2) + ')');

    var arc = d3.arc()
      .innerRadius(0)
      .outerRadius(radius);

    var pie = d3.pie()
      .value(function(d) { return d.count; })
      .sort(null);

    var tooltip = d3.select(new_tooltip_div)
      .append('div')
      .attr('class', 'd3-tooltip');

    tooltip.append('div')
      .attr('class', 'd3-label');

    /*
    tooltip.append('div')
      .attr('class', 'count');

    tooltip.append('div')
      .attr('class', 'percent');
    */

    dataset.forEach(function(d) {
      d.count = +d.count;
      d.enabled = true;
    });

    var path = svg.selectAll('path')
      .data(pie(dataset))
      .enter()
      .append('path')
      .attr('d', arc)
      .attr('fill', function(d) {
        return color(d.data.label);
      })
      .each(function(d) { this._current = d; }) //;
      .attr('data-toggle', 'tooltip')
      .attr('data-placement', 'left')
      .attr('title', function(d) { return d.data.label + ": " + d.data.count });

    path.on('mouseover', function(d) {
      var total = d3.sum(dataset.map(function(d) {
        return (d.enabled) ? d.count : 0;
      }));
      var percent = Math.round(1000 * d.data.count / total) / 10;
      tooltip.select('.d3-label').html(d.data.label + ": " + d.data.count + "-" + percent + "%");
      //tooltip.select('.d3-label').html(d.data.label);
      //tooltip.select('.count').html(d.data.count);
      //tooltip.select('.percent').html(percent + '%');
      tooltip.style('display', 'block');
    });

    path.on('mouseout', function() {
      tooltip.style('display', 'none');
    });

    /*
    path.on('mousemove', function(d) {
      tooltip.style('top', (d3.event.pageY + 10) + 'px')
        .style('left', (d3.event.pageX + 10) + 'px');
    });
    if ( !chart == "#event_type" ) {
      var tmp_svg = d3.select(chart + '-legend')
        .append("svg")
        .attr("width", 150)
        .attr("height", height/4);

    };
    */
    var legend_svg = d3.select(new_legend_div)
      .append("svg")
      .attr("width", width*1.5)
      .attr("height", height )
    /*
    function(d, i) {
          if (!chart == "#event_type") {
            return height;
          } else {
            var nheight = (legendRectSize + legendSpacing) * dataset.length;
            if (nheight > height) {
              return nheight;
            } else {
              return height;
            };
          };

      });
    */

    var legend = legend_svg.selectAll('.legend')
      .data(color.domain())
      .enter()
      .append('g')
      .attr('class', 'legend')
      .attr('transform', function(d, i) {
        var height = legendRectSize + legendSpacing;
        var offset = height * color.domain().length / 2;
        var horz = -2 * legendRectSize;
        var vert = i * height;
        return 'translate(0,' + vert + ')';
      });

    legend.append('rect')
      .attr('width', legendRectSize)
      .attr('height', legendRectSize)
      .style('fill', color)
      .style('stroke', color)
    /*
      .on('click', function(label) {
        var rect = d3.select(this)
        var enabled = true;
        var totalEnabled = d3.sum(dataset.map(function(d) {
          return (d.enabled) ? 1 : 0;
        }));

        if (rect.attr('class') == 'disabled') {
          rect.attr('class', '');
          if (chart == '#assigned') {
            var cname = '.watchuser-' + app.users[label];
            app.hidden.splice(app.hidden.indexOf(cname), 1);
            app.unhideItems(cname);
          } else {
            app.hidden.splice(app.hidden.indexOf('.watchtower-' + label), 1);
            app.unhideItems('.watchtower-' + label);
          };
        } else {
          if (totalEnabled < 2) return;
          if (chart == '#assigned') {
            var cname = '.watchuser-' + app.users[label];
            app.hidden.push(cname);
          } else {
            app.hidden.push('.watchtower-' + label);
          };
          rect.attr('class', 'disabled')
          enabled = false;
        }
        app.hideItems();

        pie.value(function(d) {
          if (d.label == label) d.enabled = enabled;
          return (d.enabled) ? d.count : 0;
        });

        path = path.data(pie(dataset));

        path.transition()
          .duration(750)
          .attrTween('d', function(d) {
            var interpolate = d3.interpolate(this._current, d);
            this._current = interpolate(0);
            return function(t) {
              return arc(interpolate(t))
            };
          });
        });
    */

    legend.append('text')
      .attr('x', legendRectSize + legendSpacing)
      .attr('y', legendRectSize - legendSpacing)
      .text(function(d) { return d; });

    new_pie_div.append(new_chart_div);
    new_pie_div.append(new_legend_div);
    new_pie_div.append(new_tooltip_div);

    return new_pie_div
  };
  /*
  $("#closeModal").on('hide.bs.modal', app.hideClosed);
  $("#closeSubmit").on('click', app.subEvent);
  $("#commentModal").on('hide.bs.modal', app.hideComment);
  $("#commentSubmit").on('click', app.subComment);
  */
  $().ready(app.createLocationPie);
  $().ready(app.createPriorityPie);
  $().ready(app.createTypePie);
  $().ready(app.createUserPie);
  $().ready(app.getConsoleData);
  $().ready(app.eventCount);
  $().ready(app.startListener);
  $(document).on('click', ".minerva-close", app.CloseEvent);
  $(document).on('click', ".minerva-investigate", app.Investigate);
  $(document).on('click', ".minerva-assign", app.AssignEvent);
  $(document).on('click', ".minerva-pcap", app.RequestPCAP);
  $(document).on('click', ".minerva-escalate", app.Escalate);
  $(document).on('click', ".minerva-comment", app.CommentEvent);
  $(document).on('click', ".minerva-pie-btn", app.hidePie);
  $(document).on('click', ".minerva-bar-btn", app.hideBar);
  $(document).on('click', ".minerva-tab-btn", app.hideTab);
  $(document).on('click', ".minerva-ref-btn", app.refreshCharts);
  $(document).on('click', ".minerva-pager", app.pagerChange);
  $(document).on('click', ".minerva-psize", app.changeSize);

}) (jQuery, minerva.console);

