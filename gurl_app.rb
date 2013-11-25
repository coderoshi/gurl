require 'rubygems'
require 'google/api_client'
require 'sinatra'
require 'logger'
require 'securerandom'
require 'sequel'
require 'sqlite3'
require 'pg'

CLIENT_ID = ENV['GURL_CLIENT_ID']
CLIENT_SECRET = ENV['GURL_SECRET']
CT_JSON = {'Content-Type' => 'application/json'}
CT_HTML = {'Content-Type' => 'text/html'}
DB_URL = ENV['DATABASE_URL'] || 'sqlite://dev.db'

class GurlApp < Sinatra::Base
  set :sessions, true

  def mirror
    settings.mirror
  end

  def GurlApp.db
    Sequel.connect(DB_URL)
  end

  def db
    Sequel.connect(DB_URL)
  end

  def user_creds(user_id=nil, gurl_token=nil)
    opts = session
    if user_id && gurl_token
      # load user_id opts
      opts = user_store(user_id)
      if opts.nil? || opts[:gurl_token] != gurl_token
        raise "User not found"
      end
      auth = settings.api_client.authorization.dup
      auth.redirect_uri = to('/oauth2callback')
      auth.update_token!(opts)
      return auth
    else
      # Build a per-request oauth credential based on token stored in session
      # which allows us to use a shared API client.
      @authorization ||= (
        auth = settings.api_client.authorization.dup
        auth.redirect_uri = to('/oauth2callback')
        auth.update_token!(session)
        auth
      )
    end
  end

  def user_store(user_id, opts=nil)
    users = db[:users]
    if opts
      rec = users.where(:user_id => user_id)
      if 1 != rec.update({
        :access_token => opts[:access_token],
        :refresh_token => opts[:refresh_token],
        :expires_in => opts[:expires_in],
        :issued_at => opts[:issued_at]
      })
        users.insert(opts)
      end
    else
      users[:user_id => user_id]
    end
  end

  configure do
    log_file = File.open('mirror.log', 'a+')
    log_file.sync = true
    logger = Logger.new(log_file)
    logger.level = Logger::DEBUG

    begin
      db.create_table :users do
        String :user_id, :primary_key => true
        String :gurl_token
        String :access_token
        String :refresh_token
        String :expires_in
        String :issued_at
      end
    rescue => e
      logger.error e.to_s
    end

    client = Google::APIClient.new
    client.authorization.client_id = CLIENT_ID
    client.authorization.client_secret = CLIENT_SECRET
    client.authorization.scope = [
      'https://www.googleapis.com/auth/glass.location',
      'https://www.googleapis.com/auth/glass.timeline',
      'https://www.googleapis.com/auth/userinfo.profile'
    ].join(' ')

    mirror = client.discovered_api('mirror', 'v1')
    oauth2 = client.discovered_api('oauth2', 'v2')

    set :logger, logger
    set :api_client, client
    set :mirror, mirror
    set :oauth2, oauth2
  end

  before do
    # Ensure user has authorized the app
    if !user_creds.access_token && request.path_info =~ /^\/mirror$/
      redirect to('/auth')
    end

    # require token unless auth or mirror
    unless request.path_info =~ /(^\/$)|(^\/mirror$)|(^\/o?auth)/
      if params[:user_id].nil? || params[:user_id].empty? || (user = user_store(params[:user_id])).nil?
        halt(403, CT_JSON, {error: 'Valid user_id required'}.to_json)
      end
      if params[:token] != user[:gurl_token]
        halt(403, CT_JSON, {error: 'Valid token required'}.to_json)
      end
    end
  end

  after do
    # Serialize the access/refresh token to the session
    session[:access_token] = user_creds.access_token
    session[:refresh_token] = user_creds.refresh_token
    session[:expires_in] = user_creds.expires_in
    session[:issued_at] = user_creds.issued_at
  end

  get '/auth' do
    # Request authorization
    redirect user_creds.authorization_uri({
      :approval_prompt => :force,
      :access_type => :offline
    }).to_s, 303
  end

  get '/oauth2callback' do
    # Exchange token
    user_creds.code = params[:code] if params[:code]
    user_creds.fetch_access_token!
    # save user opts
    result = settings.api_client.execute(:api_method => settings.oauth2.userinfo.get,
                                :parameters => {},
                                :authorization => user_creds)
    user_id = result.data.id
    session[:user_id] = user_id
    gurl_token = SecureRandom.hex(16)
    user_store(user_id, {
      :access_token => user_creds.access_token,
      :refresh_token => user_creds.refresh_token,
      :expires_in => user_creds.expires_in,
      :issued_at => user_creds.issued_at,
      :user_id => user_id,
      :gurl_token => gurl_token
    })
    opts = user_store(user_id)
    session[:gurl_token] = opts[:gurl_token]
    redirect to('/mirror')
  end

  get '/' do
    index = <<-INDEX
<html>
<body>
<h1>GURL</h1>
<a href="/auth">Add Glassware</a>
</body>
</html>
    INDEX
    [200, CT_HTML, index]
  end

  get '/mirror' do
    user_id = session[:user_id]
    token = session[:gurl_token]
    index = <<-INDEX
<html>
<body>
<h1>GURL</h1>
<h2>Creds</h2>
<ul>
<li>user_id=#{user_id}</li>
<li>token=#{token}</li>
</ul>
<h2>Links</h2>
<ul>
<li><a href="/timeline?token=#{token}&user_id=#{user_id}">/timeline</a></li>
<li><a href="/locations?token=#{token}&user_id=#{user_id}">/locations</a></li>
<li><a href="/contacts?token=#{token}&user_id=#{user_id}">/contacts</a></li>
</ul>
</body>
</html>
    INDEX
    [200, CT_HTML, index]
  end

  %w{timeline locations contacts}.each do |resource|
    get "/#{resource}" do
      resource = request.path_info.sub('/', '')
      creds = user_creds(params[:user_id], params[:token])
      result = settings.api_client.execute(:api_method => mirror.send(resource).list,
                                  :parameters => {},
                                  :authorization => creds)
      [result.status, CT_JSON, result.data.to_json]
    end

    post "/#{resource}" do
      resource = request.path_info.sub('/', '')
      creds = user_creds(params[:user_id], params[:token])
      json = JSON.parse(request.body.read)
      timeline_item = mirror.timeline.insert.request_schema.new(json)
      timeline_item.notification = {'level' => 'DEFAULT'}
      # p timeline_item
      result = settings.api_client.execute(:api_method => mirror.send(resource).insert,
                                  :body_object => timeline_item,
                                  :authorization => creds)
      [result.status, CT_JSON, result.data.to_json]

      [200, CT_JSON, {}.to_json]
    end

  end

  run! if app_file == $0
end
