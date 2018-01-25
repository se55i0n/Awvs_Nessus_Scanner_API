#!/usr/bin/env python
#coding:utf-8
#Author:se55i0n
#Nessus Api 7.0 扫描脚本

import re
import json
import time
import requests
import urlparse
import requests.packages.urllib3

class nessus(object):
	def __init__(self):
		self.task = []
		self._format = []
		#api地址
		self.server = 'https://1.1.1.1:2222'
		#api密钥
		self.secretKey = ''
		self.accessKey = ''
		self.header = {'X-ApiKeys':'accessKey={}; secretKey={};'.format(self.accessKey,
						self.secretKey), 'content-type':'application/json'}
		self.scan_rule = {
				'PCI Quarterly External Scan':'cfc46c2d-30e7-bb2b-3b92-c75da136792d080c1fffcc429cfd',
				'Host Discovery':'bbd4f805-3966-d464-b2d1-0079eb89d69708c3a05ec2812bcf',
				'WannaCry Ransomware':'861a8b95-f04c-40b0-ece6-263b1bec457c09cfc122c9666645',
				'Intel AMT Security Bypass':'3f514e0e-66e0-8ea2-b6e7-d2d86b526999a93a89944d19e1f1',
				'Basic Network Scan':'731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65',
				'Credentialed Patch Audit':'0625147c-30fe-d79f-e54f-ce7ccd7523e9b63d84cb81c23c2f',
				'Web Application Tests':'c3cbcd46-329f-a9ed-1077-554f8c2af33d0d44f09d736969bf',
				'Malware Scan':'d16c51fa-597f-67a8-9add-74d5ab066b49a918400c42a035f7',
				'Mobile Device Scan':'8382be4c-2056-51fe-65a3-a376b7912a013d58cfc392e0fac5',
				'MDM Config Audit':'fbcff9e6-0c8c-e6a9-4d8a-a43a6ee7c04b3fa5e24c0fc81b34',
				'Policy Compliance Auditing':'40345bfc-48be-37bc-9bce-526bdce37582e8fee83bcefdc746',
				'Internal PCI Network Scan':'e460ea7c-7916-d001-51dc-e43ef3168e6e20f1d97bdebf4a49',
				'Offline Config Audit':'1384f3ce-0376-7801-22db-a91e1ae16dea8d863e17313802b1',
				'Audit Cloud Infrastructure':'97f94b3b-f843-92d1-5e7a-df02f9dbfaaef40ae03bfdfa7239',
				'SCAP and OVAL Auditing':'fb9cbabc-af67-109e-f023-1e0d926c9e5925eee7a0aa8a8bd1',
				'Bash Shellshock Detection':'65d5b7ce-8d3b-d0df-f473-40633bb6122108a510a44374a167',
				'GHOST (glibc) Detection':'f10bc363-deb5-7218-b4ae-e08c85f84aa089ba9aa631170429',
				'DROWN Detection':'b9e01ede-c502-a064-cbca-e0f75d7743549709aaa0d800a65e',
				'Badlock Detection':'94077f40-5408-f59f-07b1-658c66bed20e1a2c8dfd7bf7c12a',
				'Shadow Brokers Scan':'2e823751-74a7-4d93-8067-ae301b2523037a8a9aaabacadaea',
				'Advanced Scan':'ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66'
				}
		self.W = '\033[0m'
		self.G = '\033[1;32m'
		self.O = '\033[1;33m'
		self.R = '\033[1;31m'
		self.B = '\033[1;34m'
		requests.packages.urllib3.disable_warnings()

	def request(self, method, path, data=None):
		try:
			if method == 'POST':
				return requests.post(url=self.server+path, timeout=10, 
					verify=False, headers=self.header, data=data)
			elif method == 'PUT':
				return requests.put(url=self.server+path, timeout=10, 
					verify=False, headers=self.header, data=data)
			elif method == 'DELETE':
				return requests.delete(url=self.server+path, timeout=10, 
					verify=False, headers=self.header, data=data)
			else:
				return requests.get(url=self.server+path, timeout=10, 
					verify=False, headers=self.header)
		except Exception as e:
			print e

	def scan_type(self):
		#扫描策略选择
		try:
			i = 0
			for k,v in self.scan_rule.iteritems():
				print self.G+'[{}] {}'.format(i,k)
				i += 1
			rule = raw_input(self.O+'[Nessus_Api/Set_Rule]>> '+self.W)
			if rule == '0':
				return self.scan_rule['Mobile Device Scan']
			elif rule == '1':
				return self.scan_rule['GHOST (glibc) Detection']
			elif rule == '2':
				return self.scan_rule['DROWN Detection']
			elif rule == '3':
				return self.scan_rule['Bash Shellshock Detection']
			elif rule == '4':
				return self.scan_rule['PCI Quarterly External Scan']
			elif rule == '5':
				return self.scan_rule['Internal PCI Network Scan']
			elif rule == '6':
				return self.scan_rule['Policy Compliance Auditing']
			elif rule == '7':
				return self.scan_rule['Intel AMT Security Bypass']
			elif rule == '8':
				return self.scan_rule['MDM Config Audit']
			elif rule == '9':
				return self.scan_rule['Host Discovery']
			elif rule == '10':
				return self.scan_rule['Basic Network Scan']
			elif rule == '11':
				return self.scan_rule['Web Application Tests']
			elif rule == '12':
				return self.scan_rule['Offline Config Audit']
			elif rule == '13':
				return self.scan_rule['Audit Cloud Infrastructure']
			elif rule == '14':
				return self.scan_rule['Credentialed Patch Audit']
			elif rule == '15':
				return self.scan_rule['Badlock Detection']
			elif rule == '16':
				return self.scan_rule['Shadow Brokers Scan']
			elif rule == '17':
				return self.scan_rule['SCAP and OVAL Auditing']
			elif rule == '18':
				return self.scan_rule['Malware Scan']
			elif rule == '19':
				return self.scan_rule['Advanced Scan']
			elif rule == '20':
				return self.scan_rule['WannaCry Ransomware']
			else:
				print self.R+'[-] Ops, 输入有误...'+self.W
		except Exception as e:
			pass

	def set_scan_name(self):
		#设置扫描任务名
		try:
			return raw_input(self.O+'[Nessus_Api/Set_Scan_Name]>> '+self.W)
		except Exception as e:
			pass

	def set_scan_target(self):
		#设置扫描目标
		try:
			return raw_input(self.O+'[Nessus_Api/Set_Target]>> '+self.W)
		except Exception as e:
			pass

	def check_id(self):
		#扫描任务ID选择
		try:
			r = self.request(method='GET', path='/scans')
			response = json.loads(r.text)
			text = response['scans']
			if text>0:
				for i in range(len(text)):
					self.task.append(text[i]['id'])
					print self.G+'['+str(i)+']',text[i]['name']+self.W
				task_id = raw_input(self.O+'[Nessus_Api/Set_Task_Id]>> '+self.W)
				return self.task[int(task_id)]
			else:
				print self.R+'[-] Ops, 当前无扫描任务...'+self.W
				return
		except Exception as e:
			pass
		finally:
			#清空获取的任务列表
			del self.task[:]

	def add(self):
		#添加扫描任务
		data = {
				'settings': {
			        'name': self.set_scan_name(),
			        'enabled': 'true',
			        'folder_id': 3,
			        'scanner_id': 1,
			        'text_targets': self.set_scan_target()
			        },
			    'uuid': self.scan_type()
			    }
		try:
			r = self.request(method='POST', path='/scans', data=json.dumps(data))
			return json.loads(r.text)['scan']['id'] if r.status_code == 200 else None
		except Exception as e:
			print e

	def scan(self):
		#启动扫描任务
		try:
			r = self.request(method='POST', path='/scans/{}/launch'.format(self.add()))
			if r.status_code == 200:
				print self.G+'[-] OK, 扫描任务已经启动...'+self.W
		except Exception as e:
			print e

	def stop(self):
		#停止扫描任务
		try:
			r = self.request(method='POST', path='/scans/{}/stop'.format(self.check_id()))
			if r.status_code == 200:
				print self.G+'[-] OK, 扫描已经停止...'+self.W
			elif r.status_code == 404:
				print self.R+'[-] Ops, 扫描任务不存在...'+self.W
			elif r.status_code == 409:
				print self.R+'[-] Ops, 扫描任务未启动...'+self.W
		except Exception as e:
			pass

	def pause(self):
		#停止扫描任务
		try:
			r = self.request(method='POST', path='/scans/{}/pause'.format(self.check_id()))
			if r.status_code == 200:
				print self.G+'[-] OK, 扫描已经暂停...'+self.W
			elif r.status_code == 404:
				print self.R+'[-] Ops, 扫描任务不存在...'+self.W
			elif r.status_code == 409:
				print self.R+'[-] Ops, 扫描任务未启动...'+self.W
		except Exception as e:
			pass

	def view(self):
		#查看任务状态
		try:
			r = self.request(method='GET', path='/scans/{}'.format(self.check_id()))
			response = json.loads(r.text)
			text = response['hosts']
			if text:
				for i in range(len(text)):
					progress = text[i]['progress'].split('/')[i].split('-')
					status = float(progress[0])/float(progress[1])*100
					print self.G+u'[-] 扫描目标: {}'.format(text[i]['hostname'])
					print u'[-] 扫描进度: {}'.format(str(round(status,2))+' %')
					print u'[-] 紧急漏洞: {}'.format(text[i]['critical'])
					print u'[-] 高危漏洞: {}'.format(text[i]['high'])
					print u'[-] 中危漏洞: {}'.format(text[i]['medium'])
					print u'[-] 低危漏洞: {}'.format(text[i]['low'])
					print u'[-] 信息提示: {}'.format(text[i]['info'])+self.W
		except Exception as e:
			pass

	def delete(self):
		try:
			r = self.request(method='DELETE', path='/scans/{}'.format(self.check_id()))
			if r.status_code == 200:
				print self.G+'[-] OK, 任务已经删除...'+self.W
			elif r.status_code == 500:
				print self.R+'[-] Ops, 任务删除失败...'+self.W
		except Exception as e:
			print e

	def set_format(self):
		try:
			_format = {'Nessus':'nessus','HTML':'html','CSV':'csv','Nessus DB':'db','PDF':'pdf'}
			i = 0
			for k,v in _format.iteritems():
				print self.G+'[{}] '.format(i)+k+self.W
				self._format.append(v)
				i += 1
			rule = raw_input(self.O+'[Nessus_Api/Set_Report_Format]>> '+self.W)
			return self._format[int(rule)]
		except Exception as e:
			print e
		finally:
			#清空获取的文件格式列表
			del self._format[:]

	def report(self):
		#生成报告
		try:
			scan_id = self.check_id()
			if scan_id:
				r = self.request(method='POST', path='/scans/{}/export'.format(scan_id),
				 data=json.dumps({'format':self.set_format(),'chapters':'vuln_by_host'}))
				if r.status_code == 200:
					print self.G+'[-] 报告生成中...'+self.W
					file_id = json.loads(r.text)['file']
					while True:
						time.sleep(5)
						rs = self.request(method='GET', path='/scans/{}/export/{}/download'.format(
							scan_id, file_id))
						if rs.status_code == 200:
							print self.G+'[-] OK, 生成报告成功...'+self.W
							filename = re.findall(r'attachment; filename="(.*?)"',str(rs.headers))[0]
							with open(filename,'wb') as f:
								f.write(rs.content)
							break
				elif rs.status_code == 404:
					print self.R+'[-] 扫描任务不存在...'+self.W
		except Exception as e:
			print e

	def handle(self):
		#任务调度
		try:
			self.banner()
			self.usage()
			print '-'*48
			while True:
				show = raw_input(self.O+'[Nessus_Api]>> '+self.W)
				if show == 'view':
					self.view()
				elif show == 'scan':
					self.scan()
				elif show == 'stop':
					self.stop()
				elif show == 'del':
					self.delete()
				elif show == 'pause':
					self.pause()
				elif show == 'report':
					self.report()
				elif show == 'help' or show == '?':
					self.usage()
				elif show == 'exit':
					break
				elif show == '':
					pass
				else:
					print self.R+'[-] Ops, 输入错误...'+self.W
		except KeyboardInterrupt:
			pass

	def usage(self): 
		s = '帮助:\n'
		s += '    scan     开始扫描任务\n'
		s += '    stop     停止扫描任务\n'
		s += '    pause    暂停扫描任务\n'
		s += '    del      删除扫描任务\n'
		s += '    report   任务扫描报告\n'
		s += '    view     查看扫描任务\n'
		s += '    ?、help  查看扫描帮助\n'
		s += '    exit     退出扫描任务'
		print self.B+s+self.W

	def banner(self):
		flag = '''
    _   __                          ___          _
   / | / /__  ____________  _______/   |  ____  (_)
  /  |/ / _ \/ ___/ ___/ / / / ___/ /| | / __ \/ /
 / /|  /  __(__  |__  ) /_/ (__  ) ___ |/ /_/ / /
/_/ |_/\___/____/____/\__,_/____/_/  |_/ .___/_/
                                      /_/'''
		
		print self.O+flag+self.W+'\n'
		print '-'*48

if __name__ == '__main__':
	mynessus = nessus()
	mynessus.handle()
	
