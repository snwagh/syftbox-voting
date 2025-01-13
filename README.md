![SyftBox PETs Layer](https://github.com/user-attachments/assets/c15fc32e-8017-4120-97b6-9741b8f13679)

Our goals is to design Syftbox to enable NLP interactions with all non-public data. Each client is assumed to have their own local Vector DB. Example question is as shown: 
![SyftBox PETs Layer (1)](https://github.com/user-attachments/assets/b23df2a3-25c6-4b33-b949-b2399be81f46)

Each computation will have local and global component (either we allow the network participants the flexibility to design them via templates or we can provide them ourselves if we are aiming to do a perplexity style use case)
![SyftBox PETs Layer pptx (4)](https://github.com/user-attachments/assets/60cf62a7-7216-4994-b311-427069b45a8a)

The local component is designed to interact with each local Vector DB. 
![SyftBox PETs Layer (2)](https://github.com/user-attachments/assets/e92a6aab-5f77-4db0-84f4-d2f6dd3bcec3)

And then the global or aggregate comptuation is performed on top of the local outputs. This already has a layer of privacy -- no access to raw data, only vector DB outputs so the local outputs can be revealed/aggregated in various ways. 
![SyftBox PETs Layer (3)](https://github.com/user-attachments/assets/d76835f2-aa45-4660-afba-1182dfb7bde9)


In case the above notions of privacy are insufficient or we want to innovate further on this end, for quantative comptuations, below is a proposal. 
![SyftBox PETs Layer (4)](https://github.com/user-attachments/assets/815c62e0-efc5-4ba4-8c0c-b73271cc051f)

Proposal invoves a 2 tier architecture -- heavy and lite users of Syftbox. We can decide what assumptions we make on each type of users. 
![SyftBox PETs Layer (5)](https://github.com/user-attachments/assets/d7eb91d6-bc5a-4d56-83f8-f7e1be567e2e)

Heavy users run a distributed key setup (one time). Over time we can provide the flexibility to choose your own set of 3 "heavy" users but can hardcode them initially. I can work out the research problems in this space -- the HE protocol, the distributed generation of that flavor of HE etc. We can do interesting work here and can even be published as a paper as I am sure we'll have some interesting innovations. 
![SyftBox PETs Layer pptx (1)](https://github.com/user-attachments/assets/217bfb09-53a1-436b-8292-10af1f080b6b)

The lite user experience is very easy, just do the computation and encrypt the output with the public key.  
![SyftBox PETs Layer pptx (2)](https://github.com/user-attachments/assets/5e00fe40-10e6-4f8d-9d3f-90c1290e2ef9)

For decryption, we need all 3 parties to consent to decrypting, and thus we can assume that only aggregates can be decrypted. We can also add additional interesting privacy at minimal cost -- decrypt only if at least 10 people are in this computation style things. 
![SyftBox PETs Layer pptx (3)](https://github.com/user-attachments/assets/69af3dc7-0ece-477c-ac88-80183c438dd2)

Notebooks contain the structure of distributed key setup. 
![SyftBox PETs Layer (6)](https://github.com/user-attachments/assets/648853a9-fc0c-4edb-9790-1fc00f70da0b)
