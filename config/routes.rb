Rails.application.routes.draw do
  get '/sidekiq', to: 'application#sidekiq'
  get '/admin', to: 'application#admin'

  get '/signin', to: 'application#signin'
  get '/signout', to: 'application#signout'
  root to: 'application#index'
end
