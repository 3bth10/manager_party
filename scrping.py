# import bs4  
# import requests 

# html_text = requests.get('https://goodreads.com/quotes')
# # html_text = requests.get('https://www.brainyquote.com/quote_of_the_day')

# print(html_text.text)
# app = bs4.BeautifulSoup(html_text , 'html.parser')
# app2 = app.find_all('div' , class_ = 'quoteText')

# def get_quote ():
#     pass 
  
from werkzeug.security import generate_password_hash , check_password_hash

print(generate_password_hash('mypassword123'))
# get_quote(html_text)