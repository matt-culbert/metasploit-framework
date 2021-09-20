##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # WMAP scanner is needed for all reconnaissance 
  include Msf::Auxiliary::WmapScanServer

  def initialize
    super(
      'Name'        => 'AppModule.class scanner',
      'Description' => 'Detect appmodule.class files and analize its content per CVE-2021-27850',
      'Author'       => ['Matt Culbert'],
      'License'     => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('PATH', [ true,  "The test path to find AppModule.class file", '/']),

      ])

  end

  def run_host(target_host)

    tpath = normalize_uri(datastore['PATH'])
    if tpath[-1,1] != '/'
      tpath += '/'
    end

    begin
      turl = tpath+'AppModule.class'

      res = send_request_raw({
        'uri'     => turl,
        'method'  => 'GET',
        'version' => '1.0',
      }, 10)

      if not res
        print_error("[#{target_host}] #{tpath}AppModule.class - No response")
        return
      end

      if not res.body.include?("llow:")
        vprint_status("[#{target_host}] #{tpath}AppModule.class - Doesn't contain \"llow:\"")
        return
      end

      print_status("[#{target_host}] #{tpath}AppModule.class found")
     
      result.each do |u|
        report_note(
          :host	=> target_host,
          :port	=> rport,
          :proto => 'tcp',
          :sname	=> (ssl ? 'https' : 'http'),
        )
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
