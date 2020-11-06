TAMARIN = tamarin-prover#-develop
#TFLAGS = +RTS -N10 -M20G -RTS
DECOMMENT = tools/decomment
PREFIXDIR = models-n-proofs
SEPARATOR = ==============================================================================

#configuration variables
generic = Contactless
kernel = Mastercard
auth = CDA
CVM = OnlinePIN
value = Low
authz = Offline

#other variables
decomment = Yes

#to uncomment the code blocks that follow the selected configuration
left1 = if(\(|\(([a-zA-Z0-9]+\|)+)
left2 = endif(\(|\(([a-zA-Z0-9]+\|)+)
right = (\)|(\|[a-zA-Z0-9]+)+\))

regex0 = \/\*$(left1)$(kernel)$(right) *| *$(left2)$(kernel)$(right)\*\/
regex1 = \/\*$(left1)$(auth)$(right) *| *$(left2)$(auth)$(right)\*\/
regex2 = \/\*$(left1)$(CVM)$(right) *| *$(left2)$(CVM)$(right)\*\/
regex3 = \/\*$(left1)$(value)$(right) *| *$(left2)$(value)$(right)\*\/
regex4 = \/\*$(left1)$(authz)$(right) *| *$(left2)$(authz)$(right)\*\/
regex5 = \/\*$(left1)Fix$(right) *| *$(left2)Fix$(right)\*\/

#contact
ifeq ($(generic), Contact)
	regex = ($(regex1)|$(regex2)|$(regex4))
	theory = Contact_$(auth)_$(CVM)_$(authz)
	oracle = Contact.oracle
ifndef dir
	dir = $(PREFIXDIR)/contact
endif
endif

#contactless
ifeq ($(generic), Contactless)
ifndef dir
	dir = $(PREFIXDIR)/contactless
endif
ifeq ($(kernel), Mastercard)
	regex = ($(regex0)|$(regex1)|$(regex2)|$(regex3))
	theory = Mastercard_$(auth)_$(CVM)_$(value)
	oracle = Mastercard.oracle
else

ifdef fix
	regex = ($(regex0)|$(regex1)|$(regex3)|$(regex5))
	theory = Visa_$(auth)_$(value)_Fix
else
	regex = ($(regex0)|$(regex1)|$(regex3))
	theory = Visa_$(auth)_$(value)
endif
	oracle = Visa.oracle
endif
endif

#use oracle if indicated
ifdef oracle
ifeq ($(oracle),$(wildcard $(oracle)))
  _oracle = --heuristic=O --oraclename=$(oracle)
endif
endif

#prove only one lemma if indicated
ifdef lemma
  _lemma = =$(lemma)
endif

#the Tamarin command to be executed
cmd = $(TAMARIN) --prove$(_lemma) $(dir)/$(theory).spthy $(_oracle) $(TFLAGS) --output=$(dir)/$(theory).proof

prove:
	#Create directory for specific models and their proofs
	mkdir -p $(dir)

	#Generate theory file $(theory).spthy
	sed -E 's/$(regex)//g' $(generic).spthy > $(dir)/$(theory).tmp
	sed -E 's/theory .*/theory $(theory)/' $(dir)/$(theory).tmp > $(dir)/$(theory).spthy
	
	#Remove all comments
ifeq ($(decomment), Yes)
ifeq ($(DECOMMENT),$(wildcard $(DECOMMENT)))
	$(DECOMMENT) $(dir)/$(theory).spthy > $(dir)/$(theory).tmp
	cat $(dir)/$(theory).tmp > $(dir)/$(theory).spthy
endif	
endif	
	
	#Print date and time for monitoring
	date '+Analysis started on %Y-%m-%d at %H:%M:%S'
	
	#run Tamarin
	echo '$(cmd)'
	#(time $(cmd))> $(dir)/$(theory).tmp 2>&1
	$(cmd) > $(dir)/$(theory).tmp 2>&1
	
	#add breaklines
	echo >> $(dir)/$(theory).proof
	echo >> $(dir)/$(theory).proof
	
	#add summary of results to proof file
	(sed -n '/^$(SEPARATOR)/,$$p' $(dir)/$(theory).tmp) >> $(dir)/$(theory).proof
	
	#Clean up
	$(RM) $(dir)/$(theory).tmp
	echo 'Done.'

#for clarity, will use below some redundant variable assignments

contactless:
	#mastercard:
	#SDA
	$(MAKE) auth=SDA CVM=NoPIN value=Low
	$(MAKE) auth=SDA CVM=NoPIN value=High
	$(MAKE) auth=SDA CVM=OnlinePIN value=Low
	$(MAKE) auth=SDA CVM=OnlinePIN value=High
	#DDA
	$(MAKE) auth=DDA CVM=NoPIN value=Low
	$(MAKE) auth=DDA CVM=NoPIN value=High
	$(MAKE) auth=DDA CVM=OnlinePIN value=Low
	$(MAKE) auth=DDA CVM=OnlinePIN value=High
	#CDA
	$(MAKE) auth=CDA CVM=NoPIN value=Low
	$(MAKE) auth=CDA CVM=NoPIN value=High
	$(MAKE) auth=CDA CVM=OnlinePIN value=Low
	$(MAKE) auth=CDA CVM=OnlinePIN value=High
	
	#visa:
	#EMV mode
	$(MAKE) kernel=Visa auth=EMV value=Low
	$(MAKE) kernel=Visa auth=EMV value=High
	#DDA mode
	$(MAKE) kernel=Visa auth=DDA value=Low
	$(MAKE) kernel=Visa auth=DDA value=High

	#visa-fix:
	$(MAKE) kernel=Visa auth=DDA value=Low fix=Yes

contact:
	#contact-offline:
	#SDA
	$(MAKE) generic=Contact auth=SDA CVM=NoPIN authz=Offline 
	$(MAKE) generic=Contact auth=SDA CVM=PlainPIN authz=Offline 
	$(MAKE) generic=Contact auth=SDA CVM=EncPIN authz=Offline 
	$(MAKE) generic=Contact auth=SDA CVM=OnlinePIN authz=Offline 
	#DDA
	$(MAKE) generic=Contact auth=DDA CVM=NoPIN authz=Offline 
	$(MAKE) generic=Contact auth=DDA CVM=PlainPIN authz=Offline 
	$(MAKE) generic=Contact auth=DDA CVM=EncPIN authz=Offline 
	$(MAKE) generic=Contact auth=DDA CVM=OnlinePIN authz=Offline 
	#CDA
	$(MAKE) generic=Contact auth=CDA CVM=NoPIN authz=Offline 
	$(MAKE) generic=Contact auth=CDA CVM=PlainPIN authz=Offline 
	$(MAKE) generic=Contact auth=CDA CVM=EncPIN authz=Offline 
	$(MAKE) generic=Contact auth=CDA CVM=OnlinePIN authz=Offline 

	#contact-online:
	#SDA
	$(MAKE) generic=Contact auth=SDA CVM=NoPIN authz=Online 
	$(MAKE) generic=Contact auth=SDA CVM=PlainPIN authz=Online 
	$(MAKE) generic=Contact auth=SDA CVM=EncPIN authz=Online 
	$(MAKE) generic=Contact auth=SDA CVM=OnlinePIN authz=Online 
	#DDA
	$(MAKE) generic=Contact auth=DDA CVM=NoPIN authz=Online 
	$(MAKE) generic=Contact auth=DDA CVM=PlainPIN authz=Online 
	$(MAKE) generic=Contact auth=DDA CVM=EncPIN authz=Online 
	$(MAKE) generic=Contact auth=DDA CVM=OnlinePIN authz=Online 
	#CDA
	$(MAKE) generic=Contact auth=CDA CVM=NoPIN authz=Online 
	$(MAKE) generic=Contact auth=CDA CVM=PlainPIN authz=Online 
	$(MAKE) generic=Contact auth=CDA CVM=EncPIN authz=Online 
	$(MAKE) generic=Contact auth=CDA CVM=OnlinePIN authz=Online

collect: #collect the results
	./tools/collect models-n-proofs/contact/ --output=results-contact.html #--lemmas=tools/lemmas.txt --tex-add=tools/tex-add.txt
	./tools/collect models-n-proofs/contactless/ --output=results-contactless.html #--lemmas=tools/lemmas.txt --tex-add=tools/tex-add.txt

.PHONY: clean

clean:
	$(RM) $(dir)/*.tmp
	$(RM) $(dir)/*.aes

