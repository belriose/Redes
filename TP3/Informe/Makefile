OBJECTS=tp3.pdf

all: tp3.pdf

tp3.pdf: tp3.tex ./*.sty
	pdflatex tp3.tex
	makeindex tp3.tex
	pdflatex tp3.tex
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg

clean:
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg *.pdf
