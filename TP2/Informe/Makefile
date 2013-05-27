OBJECTS=tp2.pdf

all: tp2.pdf

tp2.pdf: tp2.tex ./*.sty
	pdflatex tp2.tex
	makeindex tp2.tex
	pdflatex tp2.tex
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg

clean:
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg

borrar:
	rm -f *.aux *.log *.toc  *.out *.bbl *.blg *.lof *.ind *.ilg *.pdf
