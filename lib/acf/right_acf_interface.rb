#
# Copyright (c) 2008 RightScale Inc
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#

module RightAws

  # = RightAws::AcfInterface -- RightScale Amazon's CloudFront interface
  # The AcfInterface class provides a complete interface to Amazon's
  # CloudFront service.
  #
  # For explanations of the semantics of each call, please refer to
  # Amazon's documentation at
  # http://developer.amazonwebservices.com/connect/kbcategory.jspa?categoryID=211
  #
  # Example:
  #
  #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX')
  #
  #  list = acf.list_distributions #=>
  #    [{:status             => "Deployed",
  #      :domain_name        => "d74zzrxmpmygb.6hops.net",
  #      :aws_id             => "E4U91HCJHGXVC",
  #      :origin             => "my-bucket.s3.amazonaws.com",
  #      :cnames             => ["x1.my-awesome-site.net", "x1.my-awesome-site.net"]
  #      :comment            => "My comments",
  #      :last_modified_time => Wed Sep 10 17:00:04 UTC 2008 }, ..., {...} ]
  #
  #  distibution = list.first
  #
  #  info = acf.get_distribution(distibution[:aws_id]) #=>
  #    {:enabled            => true,
  #     :caller_reference   => "200809102100536497863003",
  #     :e_tag              => "E39OHHU1ON65SI",
  #     :status             => "Deployed",
  #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
  #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :aws_id             => "E2REJM3VUN5RSI",
  #     :comment            => "Woo-Hoo!",
  #     :origin             => "my-bucket.s3.amazonaws.com",
  #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
  #
  #  config = acf.get_distribution_config(distibution[:aws_id]) #=>
  #    {:enabled          => true,
  #     :caller_reference => "200809102100536497863003",
  #     :e_tag            => "E39OHHU1ON65SI",
  #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
  #     :comment          => "Woo-Hoo!",
  #     :origin           => "my-bucket.s3.amazonaws.com"}
  #
  #  config[:comment] = 'Olah-lah!'
  #  config[:enabled] = false
  #  config[:cnames] << "web3.my-awesome-site.net"
  #
  #  acf.set_distribution_config(distibution[:aws_id], config) #=> true
  #
  class AcfInterface < RightAwsBase
    
    include RightAwsBaseInterface

    API_VERSION      = "2009-04-02"
    DEFAULT_HOST     = 'cloudfront.amazonaws.com'
    DEFAULT_PORT     = 443
    DEFAULT_PROTOCOL = 'https'
    DEFAULT_PATH     = '/'
    DISTRIBUTION_RESOURCE = {'http' => 'distribution', 'streaming' => 'streaming-distribution']

    @@bench = AwsBenchmarkingBlock.new
    def self.bench_xml
      @@bench.xml
    end
    def self.bench_service
      @@bench.service
    end

    # Create a new handle to a CloudFront account. All handles share the same per process or per thread
    # HTTP connection to CloudFront. Each handle is for a specific account. The params have the
    # following options:
    # * <tt>:endpoint_url</tt> a fully qualified url to Amazon API endpoint (this overwrites: :server, :port, :service, :protocol). Example: 'https://cloudfront.amazonaws.com'
    # * <tt>:server</tt>: CloudFront service host, default: DEFAULT_HOST
    # * <tt>:port</tt>: CloudFront service port, default: DEFAULT_PORT
    # * <tt>:protocol</tt>: 'http' or 'https', default: DEFAULT_PROTOCOL
    # * <tt>:multi_thread</tt>: true=HTTP connection per thread, false=per process
    # * <tt>:logger</tt>: for log messages, default: RAILS_DEFAULT_LOGGER else STDOUT
    #
    #  acf = RightAws::AcfInterface.new('1E3GDYEOGFJPIT7XXXXXX','hgTHt68JY07JKUY08ftHYtERkjgtfERn57XXXXXX',
    #    {:logger => Logger.new('/tmp/x.log')}) #=>  #<RightAws::AcfInterface::0xb7b3c30c>
    #
    def initialize(aws_access_key_id=nil, aws_secret_access_key=nil, params={})
      init({ :name                => 'ACF',
             :default_host        => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).host   : DEFAULT_HOST,
             :default_port        => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).port   : DEFAULT_PORT,
             :default_service     => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).path   : DEFAULT_PATH,
             :default_protocol    => ENV['ACF_URL'] ? URI.parse(ENV['ACF_URL']).scheme : DEFAULT_PROTOCOL,
             :default_api_version => ENV['ACF_API_VERSION'] || API_VERSION },
           aws_access_key_id     || ENV['AWS_ACCESS_KEY_ID'], 
           aws_secret_access_key || ENV['AWS_SECRET_ACCESS_KEY'], 
           params)
    end

    #-----------------------------------------------------------------
    #      Requests
    #-----------------------------------------------------------------

    # Generates request hash for REST API.
    def generate_request(method, path, params={}, body=nil, headers={})  # :nodoc:
      # Params
      params.delete_if{ |key, val| val.blank? }
      unless params.blank?
        path += "?" + params.to_a.collect{ |key,val| "#{AwsUtils::amz_escape(key)}=#{AwsUtils::amz_escape(val.to_s)}" }.join("&")
      end
      # Headers
      headers['content-type'] ||= 'text/xml' if body
      headers['date'] = Time.now.httpdate
      # Auth
      signature = AwsUtils::sign(@aws_secret_access_key, headers['date'])
      headers['Authorization'] = "AWS #{@aws_access_key_id}:#{signature}"
      # Request
      path    = "#{@params[:service]}#{@params[:api_version]}/#{path}"
      request = "Net::HTTP::#{method.capitalize}".constantize.new(path)
      request.body = body if body
      # Set request headers
      headers.each { |key, value| request[key.to_s] = value }
      # prepare output hash
      { :request  => request, 
        :server   => @params[:server],
        :port     => @params[:port],
        :protocol => @params[:protocol] }
      end
      
      # Sends request to Amazon and parses the response.
      # Raises AwsError if any banana happened.
    def request_info(request, parser, &block) # :nodoc:
      request_info_impl(:acf_connection, @@bench, request, parser, &block)
    end

    #-----------------------------------------------------------------
    #      Helpers:
    #-----------------------------------------------------------------

    def self.escape(text) # :nodoc:
      REXML::Text::normalize(text)
    end

    def self.unescape(text) # :nodoc:
      REXML::Text::unnormalize(text)
    end

    def generate_call_reference # :nodoc:
      result = Time.now.strftime('%Y%m%d%H%M%S')
      10.times{ result << rand(10).to_s }
      result
    end

    def merge_headers(hash) # :nodoc:
      hash[:location] = @last_response['Location'] if @last_response['Location']
      hash[:e_tag]    = @last_response['ETag']     if @last_response['ETag']
      hash
    end

    def config_to_xml(config, type='http') # :nodoc:
      cnames = ''
      config_type = type == 'http' ? 'DistributionConfig' : 'StreamingDistributionConfig'
      unless config[:cnames].blank?
        config[:cnames].to_a.each { |cname| cnames += "  <CNAME>#{cname}</CNAME>\n" }
      end
      access_identity = ''
      unless config[:access_identity].blank?
        access_identity_str += "\n          <OriginAccessIdentity>origin-access-identity/cloudfront/#{config[:access_identity].gsub('origin-access-identity/cloudfront/','')}</OriginAccessIdentity>"
      end
      trusted_signers = ''
      if config[:trusted_signers]
        trusted_signers_str += "\n          <TrustedSigners><Self/></TrustedSigners>"
      end
      # logging
      logging = ''
      unless config[:logging].blank?
        logging = "  <Logging>\n" +
                  "    <Bucket>#{config[:logging][:bucket]}</Bucket>\n" +
                  "    <Prefix>#{config[:logging][:prefix]}</Prefix>\n" +
                  "  </Logging>\n"
      end
      # xml
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<#{config_type} xmlns=\"http://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <Origin>#{config[:origin]}</Origin>\n" +
      "  <CallerReference>#{config[:caller_reference]}</CallerReference>\n" +
      "  <Comment>#{AcfInterface::escape(config[:comment].to_s)}</Comment>\n" +
      "  <Enabled>#{config[:enabled]}</Enabled>\n" +
      cnames  +
      access_identity +
      trusted_signers +
      logging +
      "</#{config_type}>"
    end
    
    def identity_config_to_xml(config) # :nodoc:
      # xml
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
      "<CloudFrontOriginAccessIdentityConfig xmlns=\"http://#{@params[:server]}/doc/#{API_VERSION}/\">\n" +
      "  <CallerReference>#{config[:caller_reference]}</CallerReference>\n" +
      "  <Comment>#{AcfInterface::escape(config[:comment].to_s)}</Comment>\n" +
      "</CloudFrontOriginAccessIdentityConfig>"
    end

    #-----------------------------------------------------------------
    #      API Calls:
    #-----------------------------------------------------------------

    # List all distributions.
    # Returns an array of distributions or RightAws::AwsError exception.
    #
    #  acf.list_distributions #=>
    #    [{:status             => "Deployed",
    #      :domain_name        => "d74zzrxmpmygb.6hops.net",
    #      :aws_id             => "E4U91HCJHGXVC",
    #      :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #      :origin             => "my-bucket.s3.amazonaws.com",
    #      :comment            => "My comments",
    #      :last_modified_time => Wed Sep 10 17:00:04 UTC 2008 }, ..., {...} ]
    #
    def list_distributions(type='http')
      result = []
      incrementally_list_distributions(:type => 'http') do |response|
        result += response[:distributions]
        true
      end
      result
    end
    
    # List all identities.
    # Returns an array of identities or RightAws::AwsError exception.
    #
    #  acf.list_identities #=>
    #    [{:aws_id                => "E4U91HCJHGXVC",
    #      :s3_cononical_user_id  => "FIUDBVIUBSIUBSILUBSVIUBSVIUB2497y2439587",
    #      :comment               => "My comments" }, ..., {...} ]
    #
    def list_identities
      result = []
      incrementally_list_identities do |response|
        result += response[:identities]
        true
      end
      result
    end
    
    # Incrementally list distributions.
    # 
    # Optional params: +:marker+ and +:max_items+.
    #
    #   # get first distribution
    #   incrementally_list_distributions(:max_items => 1) #=>
    #      {:distributions=>
    #        [{:status=>"Deployed",
    #          :aws_id=>"E2Q0AOOMFNPSYL",
    #          :logging=>{},
    #          :origin=>"my-bucket.s3.amazonaws.com",
    #          :domain_name=>"d1s5gmdtmafnre.6hops.net",
    #          :comment=>"ONE LINE OF COMMENT",
    #          :last_modified_time=>Wed Oct 22 19:31:23 UTC 2008,
    #          :enabled=>true,
    #          :cnames=>[]}],
    #       :is_truncated=>true,
    #       :max_items=>1,
    #       :marker=>"",
    #       :next_marker=>"E2Q0AOOMFNPSYL"}
    #
    #   # get max 100 distributions (the list will be restricted by a default MaxItems value ==100 )
    #   incrementally_list_distributions
    #
    #   # list distributions by 10
    #   incrementally_list_distributions(:max_items => 10) do |response|
    #     puts response.inspect # a list of 10 distributions
    #     false # return false if the listing should be broken otherwise use true
    #   end
    #
    def incrementally_list_distributions(params={:type => 'http'}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', DISTRIBUTION_RESOURCE[params[:type]], opts)
        last_response = request_info(link,  AcfDistributionListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].blank?
      end 
      last_response 
    end
    
    
    # Incrementally list identities.
    # 
    # Optional params: +:marker+ and +:max_items+.
    #
    #   # get first identity
    #   incrementally_list_identities(:max_items => 1) #=>
    #      {:distributions=>
    #        [{:aws_id=>"E2Q0AOOMFNPSYL",
    #          :s3_cononical_user_id  => "FIUDBVIUBSIUBSILUBSVIUBSVIUB2497y2439587",
    #          :comment=>"ONE LINE OF COMMENT"}],
    #       :is_truncated=>true,
    #       :max_items=>1,
    #       :marker=>"",
    #       :next_marker=>"E2Q0AOOMFNPSYL"}
    #
    #   # get max 100 identities (the list will be restricted by a default MaxItems value ==100 )
    #   incrementally_list_identities
    #
    #   # list identities by 10
    #   incrementally_list_identities(:max_items => 10) do |response|
    #     puts response.inspect # a list of 10 identities
    #     false # return false if the listing should be broken otherwise use true
    #   end
    #
    def incrementally_list_identities(params={}, &block)
      opts = {}
      opts['MaxItems'] = params[:max_items] if params[:max_items]
      opts['Marker']   = params[:marker]    if params[:marker]
      last_response = nil
      loop do
        link = generate_request('GET', 'origin-access-identity/cloudfront', opts)
        last_response = request_info(link,  AcfOriginAccessIdentityListParser.new(:logger => @logger))
        opts['Marker'] = last_response[:next_marker]
        break unless block && block.call(last_response) && !last_response[:next_marker].blank?
      end 
      last_response 
    end
    
    # Create a new distribution.
    # Returns the just created distribution or RightAws::AwsError exception.
    #
    #  acf.create_distribution('my-bucket.s3.amazonaws.com', 'Woo-Hoo!', true, ['web1.my-awesome-site.net'],
    #                          { :prefix=>"log/", :bucket=>"my-logs.s3.amazonaws.com" } ) #=>
    #    {:comment            => "Woo-Hoo!",
    #     :enabled            => true,
    #     :location           => "https://cloudfront.amazonaws.com/2008-06-30/distribution/E2REJM3VUN5RSI",
    #     :status             => "InProgress",
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :cnames             => ["web1.my-awesome-site.net"],
    #     :logging            => { :prefix => "log/",
    #                              :bucket => "my-logs.s3.amazonaws.com"},
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008,
    #     :caller_reference   => "200809102100536497863003"}
    #
    def create_distribution(origin, comment='', enabled=true, cnames=[], caller_reference=nil, logging={}, access_identity=nil, trusted_signers=false, type='http')
      config = { :origin  => origin,
                 :comment => comment,
                 :enabled => enabled,
                 :cnames  => cnames.to_a,
                 :caller_reference => caller_reference,
                 :access_identity => access_identity,
                 :trusted_signers => trusted_signers }
      config[:logging] = logging unless logging.blank?
      create_distribution_by_config(config, type)
    end

    def create_distribution_by_config(config, type='http')
      config[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', DISTRIBUTION_RESOURCE[type], {}, config_to_xml(config, type))
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end
    
    # Create a new identity.
    # Returns the just created identity or RightAws::AwsError exception.
    #
    #  acf.create_identity('Woo-Hoo!' ) #=>
    #    {:aws_id                 =>"E2Q0AOOMFNPSYL",
    #     :s3_cononical_user_id   => "FIUDBVIUBSIUBSILUBSVIUBSVIUB2497y2439587",
    #     :comment                => "Woo-Hoo!",
    #     :caller_reference       => "200809102100536497863003"}
    #
    def create_identity(comment='', caller_reference=nil)
      config = { :comment => comment,
                 :caller_reference => caller_reference }
      create_identity_by_config(config)
    end

    def create_distribution_by_config(config)
      config[:caller_reference] ||= generate_call_reference
      link = generate_request('POST', 'origin-access-identity/cloudfront', {}, identity_config_to_xml(config))
      merge_headers(request_info(link, AcfOriginAccessIdentityListParser.new(:logger => @logger))[:identities].first)
    end
    

    # Get a distribution's information.
    # Returns a distribution's information or RightAws::AwsError exception.
    #
    #  acf.get_distribution('E2REJM3VUN5RSI') #=>
    #    {:enabled            => true,
    #     :caller_reference   => "200809102100536497863003",
    #     :e_tag              => "E39OHHU1ON65SI",
    #     :status             => "Deployed",
    #     :domain_name        => "d3dxv71tbbt6cd.6hops.net",
    #     :cnames             => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :aws_id             => "E2REJM3VUN5RSI",
    #     :comment            => "Woo-Hoo!",
    #     :origin             => "my-bucket.s3.amazonaws.com",
    #     :last_modified_time => Wed Sep 10 17:00:54 UTC 2008 }
    #
    def get_distribution(aws_id, type='http')
      link = generate_request('GET', "#{DISTRIBUTION_RESOURCE[type]}/#{aws_id}")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end
    
    # Get an identity's information.
    # Returns an identity's information or RightAws::AwsError exception.
    #
    #  acf.get_identity('E2REJM3VUN5RSI') #=>
    #    {:aws_id                 => "E2REJM3VUN5RSI",
    #     :s3_cononical_user_id   => "FIUDBVIUBSIUBSILUBSVIUBSVIUB2497y2439587",
    #     :comment                => "Woo-Hoo!"}
    #
    def get_identity(aws_id)
      link = generate_request('GET', "origin-access-identity/cloudfront/#{aws_id}")
      merge_headers(request_info(link, AcfOriginAccessIdentityListParser.new(:logger => @logger))[:identities].first)
    end

    # Get a distribution's configuration.
    # Returns a distribution's configuration or RightAws::AwsError exception.
    #
    #  acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #
    def get_distribution_config(aws_id, type='http')
      link = generate_request('GET', "#{DISTRIBUTION_RESOURCE[type]}/#{aws_id}/config")
      merge_headers(request_info(link, AcfDistributionListParser.new(:logger => @logger))[:distributions].first)
    end
    
    # Get an identity's configuration.
    # Returns an identity's configuration or RightAws::AwsError exception.
    #
    #  acf.get_identity_config('E2REJM3VUN5RSI') #=>
    #    {:caller_reference => "200809102100536497863003",
    #     :comment          => "Woo-Hoo!"}
    #
    def get_identity_config(aws_id)
      link = generate_request('GET', "origin-access-identity/cloudfront/#{aws_id}/config")
      merge_headers(request_info(link, AcfOriginAccessIdentityListParser.new(:logger => @logger))[:identities].first)
    end
    

    # Set a distribution's configuration 
    # (the :origin and the :caller_reference cannot be changed).
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  config = acf.get_distribution_config('E2REJM3VUN5RSI') #=>
    #    {:enabled          => true,
    #     :caller_reference => "200809102100536497863003",
    #     :e_tag            => "E39OHHU1ON65SI",
    #     :cnames           => ["web1.my-awesome-site.net", "web2.my-awesome-site.net"]
    #     :comment          => "Woo-Hoo!",
    #     :origin           => "my-bucket.s3.amazonaws.com"}
    #  config[:comment] = 'Olah-lah!'
    #  config[:enabled] = false
    #  acf.set_distribution_config('E2REJM3VUN5RSI', config) #=> true
    #
    def set_distribution_config(aws_id, config, type='http')
      link = generate_request('PUT', "#{DISTRIBUTION_RESOURCE[type]}/#{aws_id}/config", {}, config_to_xml(config, type),
                                     'If-Match' => config[:e_tag])
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end
    
    # Set an identity's configuration 
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  config = acf.get_identity_config('E2REJM3VUN5RSI') #=>
    #    {:caller_reference => "200809102100536497863003",
    #     :comment          => "Woo-Hoo!"}
    #  config[:comment] = 'Olah-lah!'
    #  acf.set_identity_config('E2REJM3VUN5RSI', config) #=> true
    #
    def set_identity_config(aws_id, config)
      link = generate_request('PUT', "origin-access-identity/cloudfront/#{aws_id}/config", {}, identity_config_to_xml(config),
                                     'If-Match' => config[:e_tag])
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    # Delete a distribution. The enabled distribution cannot be deleted.
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.delete_distribution('E2REJM3VUN5RSI', 'E39OHHU1ON65SI') #=> true
    #
    def delete_distribution(aws_id, e_tag, type='http')
      link = generate_request('DELETE', "#{DISTRIBUTION_RESOURCE[type]}/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end
    
    # Delete an identity. The enabled distribution cannot be deleted.
    # Returns +true+ on success or RightAws::AwsError exception.
    #
    #  acf.delete_identity('E2REJM3VUN5RSI', 'E39OHHU1ON65SI') #=> true
    #
    def delete_identity(aws_id, e_tag)
      link = generate_request('DELETE', "origin-access-identity/cloudfront/#{aws_id}", {}, nil,
                                        'If-Match' => e_tag)
      request_info(link, RightHttp2xxParser.new(:logger => @logger))
    end

    #-----------------------------------------------------------------
    #      PARSERS:
    #-----------------------------------------------------------------

    class AcfDistributionListParser < RightAWSParser # :nodoc:
      def reset
        @result = { :distributions => [] }
      end
      def tagstart(name, attributes)
        if name == 'DistributionSummary' || name == 'Distribution' || name == 'StreamingDistributionSummary' || name == 'StreamingDistribution' ||
          (name == 'DistributionConfig' && @xmlpath.blank?) || (name == 'StreamingDistributionConfig' && @xmlpath.blank?)
          @distribution = { :cnames  => [], :logging => {} }
        end
        if name == 'TrustedSigners'
          @current_signers = :trusted_signers
          @distribution[@current_signers] = []
        elsif name == 'ActiveTrustedSigners'
          @current_signers = :active_trusted_signers
          @distribution[@current_signers] = []
        elsif name == 'Signer'
          @distribution[@current_signers] << {}
        end
      end
      def tagend(name)
        case name
          when 'Marker'      then @result[:marker]       = @text
          when 'NextMarker'  then @result[:next_marker]  = @text
          when 'MaxItems'    then @result[:max_items]    = @text.to_i
          when 'IsTruncated' then @result[:is_truncated] = @text == 'true' ? true : false
          when 'Id'               then @distribution[:aws_id]             = @text
          when 'Status'           then @distribution[:status]             = @text
          when 'LastModifiedTime' then @distribution[:last_modified_time] = Time.parse(@text)
          when 'DomainName'       then @distribution[:domain_name]        = @text
          when 'Origin'           then @distribution[:origin]             = @text
          when 'Comment'          then @distribution[:comment]            = AcfInterface::unescape(@text)
          when 'CallerReference'  then @distribution[:caller_reference]   = @text
          when 'CNAME'            then @distribution[:cnames]            << @text
          when 'Enabled'          then @distribution[:enabled]            = @text == 'true' ? true : false
          when 'Bucket'           then @distribution[:logging][:bucket]   = @text
          when 'Prefix'           then @distribution[:logging][:prefix]   = @text
          when 'Self'
            if @current_signers == :active_trusted_signers
              @distribution[:active_trusted_signers].last[:id] = 'self'
              puts @distribution[@current_signers]
            else
              @distribution[@current_signers] << 'self'
            end
          when 'AwsAccountNumber'
            if @current_signers == :active_trusted_signers
              @distribution[@current_signers].last[:id] = @text
              puts @distribution[@current_signers]
            else
              @distribution[@current_signers] << @text
            end
          when 'KeyPairId'
            @distribution[@current_signers].last[:key_pairs] ||= []
            @distribution[@current_signers].last[:key_pairs] << @text
        end
        if name == 'DistributionSummary' || name == 'Distribution' ||
          (name == 'DistributionConfig' && @xmlpath.blank?)
          @result[:distributions] << @distribution
        end
      end
    end
    
    class AcfOriginAccessIdentityListParser < RightAWSParser # :nodoc:
      def reset
        @result = { :identities => [] }
      end
      def tagstart(name, attributes)
        if name == 'CloudFrontOriginAccessIdentitySummary' || name == 'CloudFrontOriginAccessIdentity' ||
          (name == 'CloudFrontOriginAccessIdentityConfig' && @xmlpath.blank?)
          @identity = {}
        end
      end
      def tagend(name)
        case name
          when 'Marker'      then @result[:marker]       = @text
          when 'NextMarker'  then @result[:next_marker]  = @text
          when 'MaxItems'    then @result[:max_items]    = @text.to_i
          when 'IsTruncated' then @result[:is_truncated] = @text == 'true' ? true : false
          when 'Id'                 then @identity[:aws_id]                 = @text
          when 'S3CanonicalUserId'  then @identity[:s3_connonical_user_id]  = @text
          when 'Comment'            then @identity[:comment]                = AcfInterface::unescape(@text)
          when 'CallerReference'    then @identity[:caller_reference]       = @text
        end
        if name == 'CloudFrontOriginAccessIdentitySummary' || name == 'CloudFrontOriginAccessIdentity' ||
          (name == 'CloudFrontOriginAccessIdentityConfig' && @xmlpath.blank?)
          @result[:identities] << @identity
        end
      end
    end
  end
end
