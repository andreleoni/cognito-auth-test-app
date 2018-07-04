require 'yaml'

class ApplicationController < ActionController::Base
  ENCRYPT_DECRYPT_KEY = 'aabbcc12345678'

  before_action :authenticate, :set_auth_cookie

  def index
    @user_email = user_email
  end

  def sidekiq
    # render '404' unless has_permission?("infra")
    render '404' unless user_groups.include?('infra')
  end

  def admin
    render '404' unless has_permission?("admin")
  end

  def signin
    redirect_to root_path
  end

  def signout
    cookies.clear
    redirect_to root_path
  end

  private

  def set_auth_cookie
    return if params[:code].blank? && (cookies[:refresh_token].blank? || cookies[:access_token].present?)

    cookies[:access_token] = { value: authorize_user['access_token'], expires: 20.seconds.from_now }
    cookies[:id_token] = { value: encrypt(authorize_user['id_token']), expires: 20.seconds.from_now }
    cookies[:refresh_token] = { value: authorize_user['refresh_token'], expires: 15.days.from_now } if cookies[:refresh_token].blank?
    response.set_header('Authorization', id_token_decrypted) if cookies[:id_token].present?
  end

  def authenticate
    redirect_to login_url if params[:code].blank? && cookies[:access_token].blank? && cookies[:refresh_token].blank?
  end

  def login_url
    "#{base_uri}/login?response_type=code&client_id=#{client_id}&redirect_uri=#{redirect_uri}"
  end

  def client_id
    '2lkmrlf49hj0q47c5nc127j1ls'
  end

  def redirect_uri
    'https://127.0.0.1:3000/signin'
  end

  def base_uri
    'https://leoni-test-pool.auth.us-east-1.amazoncognito.com'
  end

  def authorize_url
    "#{base_uri}/oauth2/token"
  end

  def authorize_body
    {
      grant_type: 'authorization_code',
      client_id: client_id,
      redirect_uri: redirect_uri,
      code: params[:code]
    }
  end

  def authorize_user
    @authorize_user ||=
      if cookies[:refresh_token].blank?
        JSON.parse(RestClient.post(authorize_url, authorize_body))
      elsif cookies[:refresh_token].present?
        JSON.parse(RestClient.post(authorize_url, refresh_token_body))
      else
        {}
      end
  rescue
    cookies.clear
  end

  def user_email
    JWT.decode(id_token_decrypted, nil, false).flatten.first["email"]
  rescue
    ""
  end

  def user_groups
    JWT.decode(id_token_decrypted, nil, false).flatten.first["cognito:groups"]
  rescue
    []
  end

  def load_permissions_yml
    @load_permissions_yml ||=
      YAML.load_file('config/permissions.yml').with_indifferent_access
  end

  def has_permission?(permission)
    return false if load_permissions_yml[permission].blank?
    load_permissions_yml[permission].include?(user_email)
  end

  def refresh_token_body
    {
      grant_type: 'refresh_token',
      client_id: client_id,
      refresh_token: cookies[:refresh_token]
    }
  end

  def encrypt(text)
    text = text.to_s unless text.is_a? String

    len   = ActiveSupport::MessageEncryptor.key_len
    salt  = SecureRandom.hex len
    key   = ActiveSupport::KeyGenerator.new(ENCRYPT_DECRYPT_KEY).generate_key salt, len
    crypt = ActiveSupport::MessageEncryptor.new key
    encrypted_data = crypt.encrypt_and_sign text
    "#{salt}$$#{encrypted_data}"
  end

  def decrypt(text)
    salt, data = text.split "$$"

    len   = ActiveSupport::MessageEncryptor.key_len
    key   = ActiveSupport::KeyGenerator.new(ENCRYPT_DECRYPT_KEY).generate_key salt, len
    crypt = ActiveSupport::MessageEncryptor.new key
    crypt.decrypt_and_verify data
  end

  def id_token_decrypted
    decrypt(cookies[:id_token])
  end
end
